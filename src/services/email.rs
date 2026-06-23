use lettre::{
    message::header::ContentType,
    transport::smtp::{authentication::Credentials, AsyncSmtpTransport},
    AsyncTransport, Message, Tokio1Executor,
};
use tracing::{error, warn};

/// Send an HTML email via SES SMTP. Returns Ok(()) even on failure when
/// SMTP credentials are not configured (dev/test environments).
#[allow(clippy::too_many_arguments)]
pub async fn send(
    smtp_host: &str,
    smtp_port: u16,
    smtp_user: Option<&str>,
    smtp_pass: Option<&str>,
    from: &str,
    to: &str,
    subject: &str,
    html_body: &str,
) -> anyhow::Result<()> {
    let email = Message::builder()
        .from(from.parse()?)
        .to(to.parse()?)
        .subject(subject)
        .header(ContentType::TEXT_HTML)
        .body(html_body.to_string())?;

    match (smtp_user, smtp_pass) {
        (Some(user), Some(pass)) => {
            let creds = Credentials::new(user.to_string(), pass.to_string());
            let mailer = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(smtp_host)?
                .port(smtp_port)
                .credentials(creds)
                .build();
            mailer.send(email).await.map_err(|e| anyhow::anyhow!(e))?;
        }
        _ => {
            warn!(to, subject, "SMTP not configured — skipping email send");
        }
    }
    Ok(())
}

pub fn verification_html(name: &str, verify_url: &str) -> String {
    format!(
        r#"<!DOCTYPE html><html><body style="font-family:sans-serif;max-width:600px;margin:0 auto;padding:24px">
<h2 style="color:#6c63ff">Confirme seu e-mail — CaaS Developer Portal</h2>
<p>Olá, <strong>{name}</strong>!</p>
<p>Clique no botão abaixo para confirmar seu endereço de e-mail e ativar sua conta:</p>
<p><a href="{verify_url}" style="display:inline-block;padding:12px 24px;background:#6c63ff;color:#fff;text-decoration:none;border-radius:6px;font-weight:bold">Confirmar e-mail</a></p>
<p style="color:#888;font-size:13px">Link válido por 24 horas. Se não criou uma conta, ignore este e-mail.</p>
<p style="color:#888;font-size:11px">tokeniza.online</p>
</body></html>"#
    )
}

pub fn temp_password_html(name: &str, temp_password: &str) -> String {
    format!(
        r#"<!DOCTYPE html><html><body style="font-family:sans-serif;max-width:600px;margin:0 auto;padding:24px">
<h2 style="color:#6c63ff">Redefinição de senha — CaaS Developer Portal</h2>
<p>Olá, <strong>{name}</strong>!</p>
<p>Sua senha provisória é:</p>
<p style="font-size:20px;font-weight:bold;letter-spacing:2px;background:#f4f4f4;padding:12px 20px;border-radius:6px;display:inline-block">{temp_password}</p>
<p>Acesse o portal e altere esta senha assim que possível.</p>
<p style="color:#888;font-size:13px">Se não solicitou a redefinição, entre em contato imediatamente.</p>
<p style="color:#888;font-size:11px">tokeniza.online</p>
</body></html>"#
    )
}

pub fn log_if_err(result: anyhow::Result<()>, context: &str) {
    if let Err(e) = result {
        error!("{context}: {e}");
    }
}
