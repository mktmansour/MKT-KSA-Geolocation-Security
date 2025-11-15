// Arabic: SMTP بسيط (اختياري لميزّة النسخ الاحتياطي عبر البريد)
// English: Minimal SMTP (optional, for backup via email)

#[cfg(feature = "smtp_std")]
pub fn smtp_send_simple(to: &str, subject: &str, body: &str) -> Result<(), String> {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    let mut s = TcpStream::connect(("127.0.0.1", 25)).map_err(|e| e.to_string())?;
    let mut _buf = [0u8; 512];
    let _ = s.read(&mut _buf);
    let _ = s.write_all(b"HELO localhost\r\n");
    let _ = s.read(&mut _buf);
    let _ = s.write_all(b"MAIL FROM:<noreply@mkt.local>\r\n");
    let _ = s.read(&mut _buf);
    let cmd = format!("RCPT TO:<{}>\r\n", to);
    let _ = s.write_all(cmd.as_bytes());
    let _ = s.read(&mut _buf);
    let _ = s.write_all(b"DATA\r\n");
    let _ = s.read(&mut _buf);
    let mail = format!(
        "Subject: {}\r\nContent-Type: text/plain\r\n\r\n{}\r\n.\r\n",
        subject, body
    );
    let _ = s.write_all(mail.as_bytes());
    let _ = s.read(&mut _buf);
    let _ = s.write_all(b"QUIT\r\n");
    Ok(())
}
