use clap::{AppSettings, Clap};
use log::{error, info, warn};
use nix::sys::signal;
use nix::unistd::Pid;
use serde_derive::{Deserialize, Serialize};
use signal_hook::iterator::Signals;
use std::fs;
use std::io::BufRead;
use std::io::Write;
use std::io::{self, Read};
use std::path;
use std::process::Command;
use std::thread;
use std::time::Duration;

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
    rotate_span: u64,
    rotate_targets: Vec<String>,
    log_inherit_kilobytes: u64,
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
use std::io::Seek;

const CHUNK_SIZE: usize = 2048;

// バックアップファイルのパスを返す
fn truncate_log(
    input_path: &path::Path,
    inherit_kilobytes: u64,
) -> io::Result<Option<path::PathBuf>> {
    if !input_path.exists() {
        warn!("Log file {} does not exist", input_path.to_string_lossy());
        return Ok(None)
    }
    let mut input = fs::File::open(&input_path)?;
    let backup_path_str = format!("{}.bak", input_path.to_string_lossy());
    let output_path_str = format!("{}.next", input_path.to_string_lossy());
    let backup_path = path::Path::new(&backup_path_str);
    let output_path = path::Path::new(&output_path_str);
    let output = fs::File::create(output_path)?;
    let mut writer = io::BufWriter::new(output);
    if input.metadata()?.len() * 1024 <= inherit_kilobytes as u64 {
        info!("skip truncate {}", input_path.to_string_lossy());
        return Ok(None);
    }

    // 後半inherit_kilobytesの位置につける
    input.seek(io::SeekFrom::End(inherit_kilobytes as i64 * 1024))?;

    let mut reader = io::BufReader::new(input);
    // 最初の一行は捨てる
    reader.read_line(&mut String::new())?;

    // CHUNK_SIZE単位で読み書きする
    let mut buf = Vec::new();
    buf.resize(CHUNK_SIZE, 0);

    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(_) => {
                writer.write_all(&buf)?;
                buf.clear();
            }
            Err(e) => return Err(e),
        }
    }
    writer.flush()?;
    fs::rename(input_path, backup_path)?;
    fs::rename(output_path, input_path)?;
    Ok(Some(backup_path.to_owned()))
}

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

fn spawn(
    exe: &str,
    args: &[String],
    truncate_span: Duration,
    truncate_targets: Vec<String>,
    inherit_kilobytes: u64,
) -> Result<(), (String, i32)> {
    let mut child = Command::new(&exe).args(args).spawn().map_err(|e| {
        (
            format!(
                "Failed to execute command {} with args({:?}) due to {:?}",
                exe, args, e
            ),
            -1,
        )
    })?;
    let pid = child.id();
    // シグナル中継用のスレッド
    thread::spawn(move || {
        // ハンドル不可能なシグナル(SIGKILL, SIGTSEGV, SIGILL, SIGFPE)を除いて全てのシグナルをキャッチ
        for sig in Signals::new(&PROPAGATION_SIGNALS)
            .expect("Cannot create signals")
            .forever()
        {
            let recieved_signal = signal_hook_term_sig_to_nix_signal(sig)
                .unwrap_or_else(|| panic!("cannot convert signal {}", sig));
            // 伝搬
            if let Err(errno) = signal::kill(Pid::from_raw(pid as i32), recieved_signal) {
                warn!(
                    "Failed to send signal to child process due to errno({})",
                    errno
                );
            }
        }
    });
    // ログローテート用のスレッド
    thread::spawn(move || loop {
        thread::sleep(truncate_span);
        match truncate_targets
            .iter()
            .map(|target| truncate_log(path::Path::new(target), inherit_kilobytes))
            .collect::<io::Result<Vec<Option<path::PathBuf>>>>()
        {
            Ok(backup_files) => {
                if let Err(errno) = signal::kill(Pid::from_raw(pid as i32), signal::SIGUSR1) {
                    error!("Cannot switch log file due to errno {}", errno);
                }
                for backup_path in backup_files.into_iter().flatten() {
                    if let Err(e) = fs::remove_file(&backup_path) {
                        warn!(
                            "Cannot remove backup file {} due to {:?}",
                            backup_path.to_string_lossy(),
                            e
                        );
                    }
                }
            }
            Err(e) => {
                error!("Cannot truncate log file: {:?}", e);
            }
        }
    });
    // シグナル中継対象プロセスを見張る
    match child.wait() {
        Ok(status) => {
            if status.success() {
                info!("The child process gracefuly exited");
                Ok(())
            } else {
                Err((
                    format!("The child process exited with {}", status),
                    status.code().unwrap_or(-1),
                ))
            }
        }
        Err(e) => Err((format!("Unknown err {:?}", e), -1)),
    }
}

fn run() -> Result<(), (String, i32)> {
    let opts: Opts = Opts::parse();
    // 設定のexampleを表示
    if opts.example {
        println!("{}", serde_yaml::to_string(&Config::exmaple()).unwrap());
        Ok(())
    } else if let Some(config) = opts.config {
        let config: Config = serde_yaml::from_str(
            &fs::read_to_string(config).map_err(|_| ("Cannot read config file".to_owned(), -1))?,
        )
        .map_err(|_| ("Invalid config file".to_owned(), -1))?;

        let mut command = config.cmd.into_iter();

        if let Some(exe) = command.next() {
            let args = command.collect::<Vec<String>>();
            spawn(
                &exe,
                args.as_slice(),
                Duration::from_secs(config.rotate_span),
                config.rotate_targets,
                config.log_inherit_kilobytes,
            )
        } else {
            Err(("Command is empty".to_owned(), -1))
        }
    } else {
        Err(("--config option must be passed".to_owned(), -1))
    }
}

fn main() {
    env_logger::init();
    if let Err((msg, exit)) = run() {
        error!("{}", msg);
        std::process::exit(exit);
    }
}
