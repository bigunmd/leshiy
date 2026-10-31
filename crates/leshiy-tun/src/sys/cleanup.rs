//! Keep failed or cancelled route removals owned by the synchronous teardown guard.
use crate::route_plan::Cidr;
use std::sync::Mutex;

pub(super) async fn remove_owned<F, Fut>(installed: &Mutex<Vec<Cidr>>, mut remove: F)
where
    F: FnMut(Cidr) -> Fut,
    Fut: std::future::Future<Output = std::io::Result<()>>,
{
    let snapshot = installed.lock().unwrap_or_else(|e| e.into_inner()).clone();
    for route in snapshot {
        if remove(route.clone()).await.is_ok() {
            installed
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .retain(|c| c != &route);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn route(last: u8) -> Cidr {
        Cidr {
            addr: std::net::Ipv4Addr::new(192, 0, 2, last).into(),
            prefix: 32,
        }
    }

    #[tokio::test]
    async fn failed_removals_remain_owned_and_successes_are_forgotten() {
        let installed = Mutex::new(vec![route(1), route(2)]);
        remove_owned(&installed, |c| async move {
            if c == route(1) {
                Err(std::io::Error::other("delete failed"))
            } else {
                Ok(())
            }
        })
        .await;
        assert_eq!(*installed.lock().unwrap(), vec![route(1)]);
    }

    #[tokio::test]
    async fn cancelled_removal_preserves_pending_and_unattempted_routes() {
        let installed = Mutex::new(vec![route(1), route(2), route(3)]);
        let mut cleanup = Box::pin(remove_owned(&installed, |c| async move {
            if c == route(2) {
                std::future::pending::<()>().await;
            }
            Ok(())
        }));
        assert!(matches!(
            std::future::poll_fn(|cx| std::task::Poll::Ready(cleanup.as_mut().poll(cx))).await,
            std::task::Poll::Pending
        ));
        drop(cleanup);
        assert_eq!(*installed.lock().unwrap(), vec![route(2), route(3)]);
        remove_owned(&installed, |_| async { Ok(()) }).await;
        assert!(installed.lock().unwrap().is_empty());
    }
}
