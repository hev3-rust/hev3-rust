use crate::dns::{Protocol, AddressFamily};
use crate::address_collection::{ConnectionTargetList, ConnectionTarget};
use std::net::IpAddr;
use tracing::{debug, trace};
use std::cmp::Ordering;
use std::collections::{HashMap, VecDeque};

/// Key for grouping by protocol and security capabilities
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ProtocolAndSecurityKey {
    protocol: Protocol,
    has_ech: bool,
}

/// Key for grouping by service
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ServiceKey {
    domain: String,
    priority: u16,
}

/// Sort addresses according to Happy Eyeballs v3 algorithm
/// 
/// This implements the 3-level grouping algorithm specified in the HEv3 RFC:
/// 1. Grouping by application protocol and security requirements 
/// 2. Grouping by service priorities
/// 3. Sorting by destination address preferences within groups
pub fn sort_addresses(
    connection_target_list: &mut ConnectionTargetList, 
    preferred_address_family_count: usize
) {
    if connection_target_list.targets.is_empty() {
        return;
    }

    debug!("Sorting {} connection targets", connection_target_list.targets.len());

    // Take ownership of all targets. We add them back to the list after sorting.
    let targets: Vec<ConnectionTarget> = connection_target_list.targets.drain(..).collect();

    let protocol_security_groups = group_by_protocol_and_security(targets);
    let service_priority_groups = group_by_service_priority(protocol_security_groups);
    let sorted_groups = sort_by_destination_preferences(
        service_priority_groups, preferred_address_family_count);

    for target in sorted_groups {
        connection_target_list.targets.push_back(target);
    }

    trace!("Sorted connection targets: {:?}", connection_target_list.targets);
}

/// Step 1: Group by application protocol and ECH support.
/// Groups with ECH support and QUIC are prioritized.
fn group_by_protocol_and_security(targets: Vec<ConnectionTarget>) -> Vec<Vec<ConnectionTarget>> {
    let mut groups = HashMap::new();

    for target in targets {
        let key = ProtocolAndSecurityKey {
            protocol: target.protocol.clone(),
            has_ech: target.has_ech_config(),
        };
        groups.entry(key).or_insert_with(Vec::new).push(target);
    }
    
    let mut groups: Vec<_> = groups.into_iter().collect();
    groups.sort_by(|a, b| {
        match (a.0.has_ech, b.0.has_ech) {
            (true, false) => return Ordering::Less,
            (false, true) => return Ordering::Greater,
            _ => {}
        }
        match (&a.0.protocol, &b.0.protocol) {
            (Protocol::Quic, Protocol::Tcp) => Ordering::Less,
            (Protocol::Tcp, Protocol::Quic) => Ordering::Greater,
            _ => Ordering::Equal,
        }
    });
    
    groups.into_iter().map(|(_, targets)| targets).collect()
}

/// Step 2: Group by service priority within each protocol/security group.
/// SVCB records with lower numerical priority values are preferred.
fn group_by_service_priority(
    protocol_security_groups: Vec<Vec<ConnectionTarget>>
) -> Vec<Vec<ConnectionTarget>> {
    let mut final_groups = Vec::new();
    
    for group in protocol_security_groups {
        let mut service_groups = HashMap::new();
        
        for target in group {
            let key = ServiceKey {
                domain: target.domain.clone(),
                priority: target.priority,
            };
            service_groups.entry(key).or_insert_with(Vec::new).push(target);
        }
        
        let mut service_groups: Vec<_> = service_groups.into_iter().collect();
        service_groups.sort_by(|a, b| {
            // If priorities are equal, randomize the order to avoid bias.
            match a.0.priority.cmp(&b.0.priority) {
                Ordering::Equal => if rand::random() { Ordering::Greater } else { Ordering::Less },
                ordering => return ordering,
            }
        });

        for (_, targets) in service_groups {
            final_groups.push(targets);
        }
    }
    
    final_groups
}

/// Step 3: Sort by destination address preferences within each group
/// Implements RFC 6724 Destination Address Selection. (TODO)
/// Could be extended to use historical data. (TODO?)
/// Addresses are interleaved within each group.
fn sort_by_destination_preferences(
    service_priority_groups: Vec<Vec<ConnectionTarget>>,
    preferred_address_family_count: usize
) -> Vec<ConnectionTarget> {
    let mut final_targets = Vec::new();
    
    for mut group in service_priority_groups {
        // TODO: Sort within the group using RFC 6724 destination address selection
        group.sort_by(|a, b| {
            // Prefer IPv6 over IPv4 (simplified RFC 6724)
            match (&a.address, &b.address) {
                (IpAddr::V6(_), IpAddr::V4(_)) => Ordering::Less,
                (IpAddr::V4(_), IpAddr::V6(_)) => Ordering::Greater,
                _ => Ordering::Equal,
            }
        });
        
        // Apply address family interleaving within the group
        let interleaved = interleave_address_families(group, preferred_address_family_count);
        final_targets.extend(interleaved);
    }
    
    final_targets
}

/// Interleave address families within a group according to HEv3 specification:
/// 1. Take preferred_count targets of the preferred family from the front of the list.
/// 2. Add the first target of the non-preferred family.
/// 3. Add the rest of the targets.
fn interleave_address_families(
    targets: Vec<ConnectionTarget>,
    preferred_count: usize
) -> Vec<ConnectionTarget> {
    if targets.is_empty() {
        return targets;
    }

    let mut targets = VecDeque::from(targets);
    
    let preferred_family = AddressFamily::from_ip(&targets[0].address);
    let mut result = Vec::with_capacity(targets.len());
    let mut targets_to_other_family = Vec::with_capacity(targets.len());

    // Take preferred_count targets of the preferred family from the front of the list.
    // If there are targets of the non-preferred family in between, move them aside to insert later.
    while result.len() < preferred_count {
        if let Some(target) = targets.pop_front() {
            if preferred_family.matches(&target.address) {
                result.push(target);
            } else {
                targets_to_other_family.push(target);
            }
        } else {
            break;
        }
    }

    // If there were any targets of the non-preferred family in between the first preferred_count 
    // targets of the preferred family, add them to the result now.
    // Otherwise, add the first target of the non-preferred family to the result.
    if !targets_to_other_family.is_empty() {
        result.extend(targets_to_other_family);
    } else {
        let mut targets_to_preferred_family = targets_to_other_family; // reuse the vec from before
        while let Some(target) = targets.pop_front() {
            if !preferred_family.matches(&target.address) {
                result.push(target);
                break;
            } else {
                targets_to_preferred_family.push(target);
            }
        }
        result.extend(targets_to_preferred_family);
    }

    // Add all remaining targets (independent of family) to result.
    result.extend(targets);
    
    result
}

// TODO: check validity of unit tests
#[cfg(test)]
mod tests {
    use super::*;

    fn create_connection_target(
        domain: &str,
        ip: &str, 
        protocol: Protocol, 
        priority: u16,
        ech_config: Option<Vec<u8>>
    ) -> ConnectionTarget {
        ConnectionTarget{
            domain: domain.to_string(),
            address: ip.parse().unwrap(),
            protocol,
            priority,
            ech_config,
            is_from_svcb: false,
            used: false,
        }
    }

    fn create_connection_target_list(targets: Vec<ConnectionTarget>) -> ConnectionTargetList {
        let mut list = ConnectionTargetList::new(vec![]);
        for target in targets {
            list.targets.push_back(target);
        }
        list
    }

    #[test]
    fn test_empty_input() {
        let mut list = ConnectionTargetList::new(vec![]);
        sort_addresses(&mut list, 1);
        assert!(list.targets.is_empty());
    }

    #[test] 
    fn test_single_target() {
        let target = create_connection_target("example.com", "192.168.1.1", Protocol::Tcp, 10, None);
        let mut list = create_connection_target_list(vec![target]);
        
        sort_addresses(&mut list, 1);
        
        assert_eq!(list.targets.len(), 1);
        assert_eq!(list.targets[0].address.to_string(), "192.168.1.1");
    }

    #[test]
    fn test_protocol_security_grouping() {
        let targets = vec![
            create_connection_target("example.com", "192.168.1.1", Protocol::Tcp, 10, None),
            create_connection_target("example.com", "192.168.1.2", Protocol::Tcp, 10, Some(vec![1, 2, 3])), // ECH
            create_connection_target("example.com", "192.168.1.3", Protocol::Quic, 10, None),
        ];
        let mut list = create_connection_target_list(targets);
        
        sort_addresses(&mut list, 1);
        
        assert_eq!(list.targets.len(), 3);
        // ECH should come first, then by protocol priority (QUIC > TCP)
        assert!(list.targets[0].has_ech_config());
        assert_eq!(list.targets[1].protocol, Protocol::Quic);
        assert_eq!(list.targets[2].protocol, Protocol::Tcp);
        assert!(!list.targets[2].has_ech_config());
    }

    #[test]
    fn test_service_priority_grouping() {
        let targets = vec![
            create_connection_target("example.com", "192.168.1.1", Protocol::Tcp, 20, None),
            create_connection_target("example.com", "192.168.1.2", Protocol::Tcp, 10, None), // Lower priority first
            create_connection_target("example.com", "192.168.1.3", Protocol::Tcp, 30, None),
        ];
        let mut list = create_connection_target_list(targets);
        
        sort_addresses(&mut list, 1);
        
        assert_eq!(list.targets.len(), 3);
        // Should be sorted by priority (lower values first)
        assert_eq!(list.targets[0].priority, 10);
        assert_eq!(list.targets[1].priority, 20);
        assert_eq!(list.targets[2].priority, 30);
    }

    #[test]
    fn test_address_family_preference() {
        let targets = vec![
            create_connection_target("example.com", "192.168.1.1", Protocol::Tcp, 10, None),
            create_connection_target("example.com", "2001:db8::1", Protocol::Tcp, 10, None), // IPv6 preferred
        ];
        let mut list = create_connection_target_list(targets);
        
        sort_addresses(&mut list, 1);
        
        assert_eq!(list.targets.len(), 2);
        // IPv6 should come first
        assert!(list.targets[0].address.is_ipv6());
        assert!(list.targets[1].address.is_ipv4());
    }

    #[test]
    fn test_full_3level_grouping() {
        let targets = vec![
            // Group 1: TCP + ECH, priority 20
            create_connection_target("example.com", "192.168.1.1", Protocol::Tcp, 20, Some(vec![1,2,3])),
            create_connection_target("example.com", "2001:db8::1", Protocol::Tcp, 20, Some(vec![1,2,3])),
            
            // Group 2: TCP + ECH, priority 10 (higher priority)  
            create_connection_target("example.com", "192.168.1.2", Protocol::Tcp, 10, Some(vec![1,2,3])),
            create_connection_target("example.com", "2001:db8::2", Protocol::Tcp, 10, Some(vec![1,2,3])),
            
            // Group 3: QUIC, no ECH, priority 10
            create_connection_target("example.com", "192.168.1.3", Protocol::Quic, 10, None),
            create_connection_target("example.com", "2001:db8::3", Protocol::Quic, 10, None),
        ];
        let mut list = create_connection_target_list(targets);
        
        sort_addresses(&mut list, 1);
        
        assert_eq!(list.targets.len(), 6);
        
        // First should be ECH+TCP, priority 10, IPv6 first
        assert!(list.targets[0].has_ech_config());
        assert_eq!(list.targets[0].protocol, Protocol::Tcp);
        assert_eq!(list.targets[0].priority, 10);
        assert!(list.targets[0].address.is_ipv6());
        
        // Second should be ECH+TCP, priority 10, IPv4 (interleaving)
        assert!(list.targets[1].has_ech_config()); 
        assert_eq!(list.targets[1].protocol, Protocol::Tcp);
        assert_eq!(list.targets[1].priority, 10);
        assert!(list.targets[1].address.is_ipv4());
    }
}