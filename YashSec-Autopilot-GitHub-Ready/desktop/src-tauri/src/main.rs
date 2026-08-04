#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use rand::{distributions::Alphanumeric, Rng};
use std::{
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Mutex,
    thread,
    time::{Duration, Instant},
};
use tauri::{Manager, RunEvent, WebviewUrl, WebviewWindowBuilder};

struct BackendProcess(Mutex<Option<Child>>);

fn random_token() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect()
}

fn available_port() -> Result<u16, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    listener.local_addr().map(|addr| addr.port()).map_err(|e| e.to_string())
}

fn existing_backend_path(exe_dir: &Path) -> Option<PathBuf> {
    [
        exe_dir.join("YashSecBackend.exe"),
        exe_dir.join("resources").join("YashSecBackend.exe"),
        exe_dir.join("..").join("resources").join("YashSecBackend.exe"),
    ]
    .into_iter()
    .find(|path| path.exists())
}

fn data_dir() -> Result<PathBuf, String> {
    let local = std::env::var_os("LOCALAPPDATA")
        .or_else(|| std::env::var_os("APPDATA"))
        .ok_or_else(|| "Windows LocalAppData could not be resolved.".to_string())?;
    Ok(PathBuf::from(local).join("YashSec Autopilot").join("data"))
}

fn launch_backend(exe_dir: &Path, port: u16, token: &str) -> Result<Child, String> {
    let backend = existing_backend_path(exe_dir).ok_or_else(|| {
        format!(
            "YashSecBackend.exe was not found next to the desktop executable ({})",
            exe_dir.display()
        )
    })?;
    let data = data_dir()?;
    std::fs::create_dir_all(&data).map_err(|e| e.to_string())?;
    Command::new(backend)
        .arg("--host").arg("127.0.0.1")
        .arg("--port").arg(port.to_string())
        .arg("--transport-token").arg(token)
        .arg("--data-dir").arg(data)
        .arg("--log-level").arg("warning")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("Could not start YashSecBackend.exe: {e}"))
}

fn wait_for_backend(port: u16, token: &str, timeout: Duration) -> Result<(), String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .map_err(|e| e.to_string())?;
    let started = Instant::now();
    let url = format!("http://127.0.0.1:{port}/api/health");
    while started.elapsed() < timeout {
        if let Ok(response) = client.get(&url).header("X-YashSec-Transport", token).send() {
            if response.status().is_success() {
                return Ok(());
            }
        }
        thread::sleep(Duration::from_millis(220));
    }
    Err("The backend did not become healthy within 30 seconds.".to_string())
}

fn stop_backend(app: &tauri::AppHandle) {
    if let Some(state) = app.try_state::<BackendProcess>() {
        if let Ok(mut guard) = state.0.lock() {
            if let Some(child) = guard.as_mut() {
                let _ = child.kill();
                let _ = child.wait();
            }
            *guard = None;
        }
    }
}

fn main() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_opener::init())
        .manage(BackendProcess(Mutex::new(None)))
        .setup(|app| {
            let current_exe = std::env::current_exe().map_err(|e| e.to_string())?;
            let exe_dir = current_exe.parent().ok_or("Cannot resolve desktop executable directory")?;
            let port = available_port()?;
            let token = random_token();
            let child = launch_backend(exe_dir, port, &token)?;
            if let Some(state) = app.try_state::<BackendProcess>() {
                *state.0.lock().map_err(|e| e.to_string())? = Some(child);
            }
            if let Err(error) = wait_for_backend(port, &token, Duration::from_secs(30)) {
                stop_backend(app.handle());
                return Err(error.into());
            }
            let encoded_token: String = url::form_urlencoded::byte_serialize(token.as_bytes()).collect();
            let url = format!("http://127.0.0.1:{port}/?transport={encoded_token}")
                .parse()
                .map_err(|e| format!("Invalid local URL: {e}"))?;
            WebviewWindowBuilder::new(app, "main", WebviewUrl::External(url))
                .title("YashSec Autopilot")
                .inner_size(1440.0, 900.0)
                .min_inner_size(850.0, 620.0)
                .resizable(true)
                .center()
                .build()?;
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building YashSec Autopilot");

    let handle = app.handle().clone();
    app.run(move |_app, event| match event {
        RunEvent::ExitRequested { .. } | RunEvent::Exit => stop_backend(&handle),
        _ => {}
    });
}
