use std::{io, path::Path};

use fanotify::{
    high_level::{Event, Fanotify, FanotifyMode, FanotifyResponse},
    low_level::{FAN_ACCESS, FAN_MODIFY},
};
use nix::{
    errno::Errno,
    poll::{poll, PollFd, PollFlags},
};
use scopeguard::defer;
use thiserror::Error;
use tracing::debug;

static DOCKER_SOCKET: &str = "/var/run/docker.sock";

pub struct DockerWatcher {
    fd: Fanotify,
}

#[derive(Error, Debug)]
pub enum HandleDockerEventError {
    #[error(transparent)]
    Errno(#[from] Errno),
}

impl DockerWatcher {
    pub fn new() -> Result<Self, io::Error> {
        let fd = Fanotify::new_with_blocking(FanotifyMode::CONTENT);
        let p = Path::new(DOCKER_SOCKET);
        if p.exists() {
            fd.add_path(FAN_ACCESS, DOCKER_SOCKET)?;
        }

        Ok(DockerWatcher { fd })
    }

    fn handle_event(&self, event: Event) -> Result<(), HandleDockerEventError> {
        defer!(self.fd.send_response(event.fd, FanotifyResponse::Allow));

        debug!("received docker event: {:#?}", event);

        Ok(())
    }

    pub fn work_loop(&self) -> Result<(), HandleDockerEventError> {
        debug!("starting docker work loop");
        let mut fds = [PollFd::new(self.fd.as_raw_fd(), PollFlags::POLLIN)];
        loop {
            let poll_num = poll(&mut fds, -1)?;
            if poll_num > 0 {
                for event in self.fd.read_event() {
                    self.handle_event(event)?;
                }
            } else {
                debug!("poll_num <= 0!");
                break;
            }
        }

        Ok(())
    }
}
