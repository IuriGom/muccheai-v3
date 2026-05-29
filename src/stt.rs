//! Speech-to-Text module.

use std::process::Command;

/// Transcribe raw audio bytes.
pub async fn transcribe(audio_bytes: Vec<u8>) -> anyhow::Result<String> {
    let tmp_dir = std::env::temp_dir();
    let input_path = tmp_dir.join(format!("muccheai_stt_{}.webm", uuid::Uuid::new_v4()));
    let wav_path = input_path.with_extension("wav");

    tokio::fs::write(&input_path, &audio_bytes).await?;

    // Convert to 16 kHz mono WAV with ffmpeg.
    let ffmpeg_status = tokio::task::spawn_blocking({
        let input = input_path.clone();
        let output = wav_path.clone();
        move || {
            Command::new("ffmpeg")
                .arg("-y")
                .arg("-i")
                .arg(&input)
                .arg("-ar")
                .arg("16000")
                .arg("-ac")
                .arg("1")
                .arg("-c:a")
                .arg("pcm_s16le")
                .arg(&output)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
        }
    })
    .await?;

    match ffmpeg_status {
        Ok(s) if s.success() => {}
        _ => {
            let _ = tokio::fs::remove_file(&input_path).await;
            return Err(anyhow::anyhow!(
                "ffmpeg failed: ensure ffmpeg is installed and the uploaded file is a valid audio format"
            ));
        }
    }

    // Run whisper CLI.
    let whisper_output = tokio::task::spawn_blocking({
        let wav = wav_path.clone();
        move || {
            Command::new("whisper")
                .arg(&wav)
                .arg("--model")
                .arg("base")
                .arg("--output_format")
                .arg("txt")
                .arg("--output_dir")
                .arg(tmp_dir)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .output()
        }
    })
    .await?;

    let _ = tokio::fs::remove_file(&input_path).await;
    let _ = tokio::fs::remove_file(&wav_path).await;

    let output = match whisper_output {
        Ok(o) => o,
        Err(e) => {
            return Err(anyhow::anyhow!(
                "whisper CLI not found or failed to start: {}. Install whisper (e.g. `pip install openai-whisper`) and ensure it is on $PATH.",
                e
            ));
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!(
            "whisper exited with status {}: {}",
            output.status,
            stderr.trim()
        ));
    }

    // Whisper writes a .txt file next to the input; try to read it.
    let txt_path = wav_path.with_extension("txt");
    let txt_result = if let Ok(text) = tokio::fs::read_to_string(&txt_path).await {
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            Some(trimmed.to_string())
        } else {
            None
        }
    } else {
        None
    };
    let _ = tokio::fs::remove_file(&txt_path).await;
    if let Some(text) = txt_result {
        return Ok(text);
    }

    // Fallback: parse stdout.
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let line = line.trim();
        // Skip timestamped lines like "[00:00:00.000 --> 00:00:05.000]  hello world"
        let cleaned = if let Some(idx) = line.find(']') {
            line[idx + 1..].trim()
        } else {
            line
        };
        if !cleaned.is_empty() && !cleaned.starts_with("Loading model") {
            return Ok(cleaned.to_string());
        }
    }

    Err(anyhow::anyhow!(
        "whisper ran successfully but produced no transcription text"
    ))
}
