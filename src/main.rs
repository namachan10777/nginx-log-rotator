use clap::{AppSettings, Clap};
use log::{error, info, warn};
use nix::sys::signal;
use nix::unistd::Pid;
use serde_derive::{Deserialize, Serialize};
use signal_hook::iterator::Signals;
use std::fs;
use std::process::Command;
use std::thread;

#[derive(Clap)]
#[clap(version = "0.1.0", author = "Masaki Nakano <admin@namachan10777.dev>")]
#[clap(setting = AppSettings::ColoredHelp)]
struct Opts {
    #[clap(short, long)]
    config: Option<String>,
    #[clap(long)]
    example: bool,
}

#[derive(Serialize, Deserialize)]
struct Config {
    cmd: Vec<String>,
    rotate_span: usize,
    rotate_targets: Vec<String>,
    log_inherit_kilobytes: usize,
}

impl Config {
    fn exmaple() -> Self {
        Self {
            cmd: vec![
                "nginx".to_owned(),
                "-g".to_owned(),
                "'daemon off;'".to_owned(),
            ],
            rotate_span: 1800,
            rotate_targets: vec!["/var/log/mtail/access.log".to_owned()],
            log_inherit_kilobytes: 256,
        }
    }
}

use signal_hook::consts::signal as sigs;

fn signal_hook_term_sig_to_nix_signal(sig: i32) -> Option<signal::Signal> {
    match sig {
        sigs::SIGABRT => Some(signal::SIGABRT),
        sigs::SIGALRM => Some(signal::SIGALRM),
        sigs::SIGBUS => Some(signal::SIGBUS),
        sigs::SIGCHLD => Some(signal::SIGCHLD),
        sigs::SIGCONT => Some(signal::SIGCONT),
        sigs::SIGHUP => Some(signal::SIGHUP),
        sigs::SIGINT => Some(signal::SIGINT),
        sigs::SIGIO => Some(signal::SIGIO),
        sigs::SIGPIPE => Some(signal::SIGPIPE),
        sigs::SIGPROF => Some(signal::SIGPROF),
        sigs::SIGQUIT => Some(signal::SIGQUIT),
        sigs::SIGSYS => Some(signal::SIGSYS),
        sigs::SIGTERM => Some(signal::SIGTERM),
        sigs::SIGTRAP => Some(signal::SIGTRAP),
        sigs::SIGTSTP => Some(signal::SIGTSTP),
        sigs::SIGTTIN => Some(signal::SIGTTIN),
        sigs::SIGTTOU => Some(signal::SIGTTOU),
        sigs::SIGURG => Some(signal::SIGURG),
        sigs::SIGUSR1 => Some(signal::SIGUSR1),
        sigs::SIGUSR2 => Some(signal::SIGUSR2),
        sigs::SIGVTALRM => Some(signal::SIGVTALRM),
        sigs::SIGWINCH => Some(signal::SIGWINCH),
        sigs::SIGXCPU => Some(signal::SIGXCPU),
        sigs::SIGXFSZ => Some(signal::SIGXFSZ),
        _ => None,
    }
}

const PROPAGATION_SIGNALS: [i32; 24] = [
    sigs::SIGABRT,
    sigs::SIGALRM,
    sigs::SIGBUS,
    sigs::SIGCHLD,
    sigs::SIGCONT,
    sigs::SIGHUP,
    sigs::SIGINT,
    sigs::SIGIO,
    sigs::SIGPIPE,
    sigs::SIGPROF,
    sigs::SIGQUIT,
    sigs::SIGSYS,
    sigs::SIGTERM,
    sigs::SIGTRAP,
    sigs::SIGTSTP,
    sigs::SIGTTIN,
    sigs::SIGTTOU,
    sigs::SIGURG,
    sigs::SIGUSR1,
    sigs::SIGUSR2,
    sigs::SIGVTALRM,
    sigs::SIGWINCH,
    sigs::SIGXCPU,
    sigs::SIGXFSZ,
];

fn spawn(exe: &str, args: &[String]) -> Result<(), String> {
    let mut child = Command::new(&exe).args(args).spawn().map_err(|e| {
        format!(
            "Failed to execute command {} with args({:?}) due to {:?}",
            exe, args, e
        )
    })?;
    let pid = child.id();
    thread::spawn(move || {
        for sig in Signals::new(&PROPAGATION_SIGNALS)
            .expect("Cannot create signals")
            .forever()
        {
            let recieved_signal = signal_hook_term_sig_to_nix_signal(sig)
                .expect(&format!("cannot convert signal {}", sig));
            if let Err(errno) = signal::kill(Pid::from_raw(pid as i32), recieved_signal) {
                warn!(
                    "Failed to send signal to child process due to errno({})",
                    errno
                );
            }
        }
    });
    match child.wait() {
        Ok(status) => {
            if status.success() {
                info!("The child process gracefuly exited");
                Ok(())
            } else {
                Err(format!("The child process exited with {}", status))
            }
        }
        Err(e) => Err(format!("Unknown err {:?}", e)),
    }
}

fn run() -> Result<(), String> {
    let opts: Opts = Opts::parse();
    if opts.example {
        println!("{}", serde_yaml::to_string(&Config::exmaple()).unwrap());
        Ok(())
    } else if let Some(config) = opts.config {
        let config: Config = serde_yaml::from_str(
            &fs::read_to_string(config).map_err(|_| "Cannot read config file".to_owned())?,
        )
        .map_err(|_| "Invalid config file".to_owned())?;

        let mut command = config.cmd.into_iter();

        if let Some(exe) = command.next() {
            let args = command.collect::<Vec<String>>();
            spawn(&exe, args.as_slice())
        } else {
            Err("Command is empty".to_owned())
        }
    } else {
        Err("--config option must be passed".to_owned())
    }
}

fn main() {
    env_logger::init();
    if let Err(msg) = run() {
        error!("{}", msg);
        std::process::exit(-1);
    }
}
