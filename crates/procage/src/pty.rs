//! The controller side of a run's new pseudo-terminal (`Tty::NewPty`).

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};

/// The controller side of a caged child's terminal, taken with
/// `Child::take_pty`.
///
/// What is written here is the child's terminal input; what is read is its
/// terminal output. The terminal starts at 80 columns by 24 rows;
/// [`Pty::set_size`] changes it, and the child's foreground process group
/// gets `SIGWINCH` from the kernel. procage forwards nothing on its own.
///
/// The bytes read are the cage's **untrusted output**, escape sequences
/// included, and procage does not filter them. Do not pass them unfiltered
/// to a terminal whose emulator acts on sequences (clipboard writes, title
/// reports, answerback) or to anything that runs them.
///
/// Once every process of the run has exited, reads return end of file or
/// fail (`EIO` on Linux). Read while the run runs: on macOS, output still
/// unread when the last process exits is kept for about 0.6 s and then
/// discarded (measured on macOS 26.6.2); Linux keeps it until read.
/// Dropping the `Pty` closes the terminal: the child's session gets
/// `SIGHUP`. Use `&Pty` to read and write from two threads; for async I/O,
/// set the descriptor non-blocking and register it with the runtime's
/// reactor.
#[derive(Debug)]
pub struct Pty {
    controller: File,
    device: PathBuf,
}

impl Pty {
    /// A new terminal: its controller and the other end (the device),
    /// close-on-exec, 80 by 24.
    pub(crate) fn open() -> io::Result<(Pty, OwnedFd)> {
        let (controller, device, path) = crate::native::open_terminal()?;
        Ok((
            Pty {
                controller: File::from(controller),
                device: path,
            },
            device,
        ))
    }

    /// The path of the child's terminal device (`/dev/ttysN` on macOS,
    /// `/dev/pts/N` on Linux).
    pub fn device(&self) -> &Path {
        &self.device
    }

    /// Sets the terminal's window size.
    pub fn set_size(&self, rows: u16, cols: u16) -> io::Result<()> {
        crate::native::set_window(self.controller.as_raw_fd(), rows, cols)
    }
}

impl Read for Pty {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.controller.read(buf)
    }
}

impl Read for &Pty {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (&self.controller).read(buf)
    }
}

impl Write for Pty {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.controller.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.controller.flush()
    }
}

impl Write for &Pty {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (&self.controller).write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        (&self.controller).flush()
    }
}

impl AsFd for Pty {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.controller.as_fd()
    }
}

impl AsRawFd for Pty {
    fn as_raw_fd(&self) -> RawFd {
        self.controller.as_raw_fd()
    }
}

impl From<Pty> for OwnedFd {
    fn from(pty: Pty) -> OwnedFd {
        pty.controller.into()
    }
}
