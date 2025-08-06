use crate::address_collection::{ConnectionTarget, ConnectionTargetList};
use crate::address_sorting;
use crate::connection::{self, Hev3Stream};
use crate::dns::{DnsResult, Protocol};
use crate::hev3_client::{Hev3Config, Hev3Error, Result};
use std::pin::Pin;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::task::JoinHandle;
use tracing::{info, warn};

pub async fn race_connections(
    mut connection_targets: ConnectionTargetList,
    hostname: &str,
    dns_rx: &mut Receiver<DnsResult>,
    config: &Hev3Config,
) -> Result<Hev3Stream> {
    if connection_targets.is_empty() {
        return Err(Hev3Error::NoRouteAvailable);
    }
    let mut handles: Vec<JoinHandle<()>> = Vec::with_capacity(connection_targets.len());
    let (tx, mut rx) = tokio::sync::mpsc::channel(connection_targets.len());

    let first_target = connection_targets.pop_next_target().unwrap();

    handles.push(start_connection_concurrently(first_target, hostname, &tx));

    let mut connection_timeout = Box::pin(tokio::time::sleep(config.connection_timeout));
    let mut connection_attempt_delay = create_cad(config);

    loop {
        // Break if
        // 1. there are no more connection targets left, and
        // 2. all connection attempts are finished, and
        // 3. the connection attempt channel is empty (no results in buffer), and
        // 4. the dns result channel is closed (all DNS lookups are finished)
        // -> nothing left to wait for
        if connection_targets.is_empty()
            && all_handles_finished(&handles)
            && rx.is_empty()
            && dns_rx.is_closed()
        {
            break;
        }

        // Wait for one of the following events:
        // 1. A connection attempt returns a result (success or failure)
        // 2. A new DNS result arrives from the concurrent DNS resolver
        // 3. The connection attempt delay expires
        // 4. The connection timeout expires
        tokio::select! {
            // Result from a connection attempt
            Some(result) = rx.recv() => {
                match result {
                    Ok(_) => {
                        abort_all_pending_tasks(&mut handles);
                        return result;
                    }
                    Err(e) => info!("Connection attempt failed: {}", e),
                }
            }
            // New DNS result -> include into connection targets list
            // If there are no connection attempts left and the CAD is elapsed, start the next connection attempt
            // FIXME: might introduce a duplicate connection attempt if:
            //     An A or AAAA record arrives and a connection is attempted
            //     The connection attempt fails
            //     An HTTPS record arrives with the same IP in an ipvXhint
            //     A new connection attempt to the same target is started
            //     (or vice versa: first HTTPS, then A/AAAA)
            //     -> keep track of failed connection attempts?
            Some(dns_result) = dns_rx.recv() => {
                connection_targets.add_dns_result(dns_result);
                address_sorting::sort_addresses(
                    &mut connection_targets, 
                    config.preferred_protocol_combination_count
                );
                if all_handles_finished(&handles) 
                    && connection_attempt_delay.is_elapsed() 
                    && !connection_targets.is_empty()
                {
                    let next_target = connection_targets.pop_next_target().unwrap();
                    handles.push(start_connection_concurrently(next_target, hostname, &tx));
                    connection_attempt_delay = create_cad(config);
                }
            }
            // Connection attempt delay expires -> start a new connection attempt
            _ = &mut connection_attempt_delay => {
                if !connection_targets.is_empty() {
                    let next_target = connection_targets.pop_next_target().unwrap();
                    handles.push(start_connection_concurrently(next_target, hostname, &tx));
                    connection_attempt_delay = create_cad(config);
                }
            }
            // Connection timeout expires -> abort
            _ = &mut connection_timeout => {
                warn!("Connection attempt to {} aborted after {}s inactivity", 
                    hostname, config.connection_timeout.as_secs());
                return Err(Hev3Error::Timeout);
            }
        }
    }

    abort_all_pending_tasks(&mut handles);

    Err(Hev3Error::NoRouteAvailable)
}

fn start_connection_concurrently(
    target: ConnectionTarget,
    hostname: &str,
    tx: &Sender<Result<Hev3Stream>>,
) -> JoinHandle<()> {
    let hostname = hostname.to_string();
    let tx = tx.clone();

    let handle = tokio::spawn(async move {
        let stream = match target.protocol {
            Protocol::Quic => connection::connect_quic(target.address, &hostname).await,
            Protocol::Tcp => connection::connect_tcp_tls(target.address).await,
        };
        let _ = tx.send(stream).await;
    });
    handle
}

fn create_cad(config: &Hev3Config) -> Pin<Box<tokio::time::Sleep>> {
    Box::pin(tokio::time::sleep(config.connection_attempt_delay))
}

fn all_handles_finished(handles: &Vec<JoinHandle<()>>) -> bool {
    handles.iter().all(|handle| handle.is_finished())
}

fn abort_all_pending_tasks(handles: &mut Vec<JoinHandle<()>>) {
    for handle in handles {
        if !handle.is_finished() {
            handle.abort();
        }
    }
}
