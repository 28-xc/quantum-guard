import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# 生产环境务必使用环境变量覆盖，避免敏感信息进仓库。
# 发件人（用户收到的验证码邮件显示的「来自」）= SMTP_FROM 或 SMTP_USER，即「发验证码的邮箱」，如 2533828855@qq.com；
# 收件人 = 调用 send_email(to_email, ...) 时传入的 to_email，即用户填写的安全邮箱，如 1234567@qq.com。
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.qq.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "465"))
SMTP_USER = os.environ.get("SMTP_USER", "")   # 发验证码的邮箱（SMTP 登录账号），如 2533828855@qq.com
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")  # QQ 邮箱请使用授权码，非登录密码
SMTP_FROM = os.environ.get("SMTP_FROM") or SMTP_USER  # 发件人显示地址，不设则与 SMTP_USER 一致


def send_email(to_email: str, subject: str, body_text: str) -> None:
    """通过 SMTP_SSL 发送纯文本邮件。发件人为 SMTP_FROM，收件人为 to_email（用户填写的邮箱）。"""
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = to_email
    msg.attach(MIMEText(body_text, "plain", "utf-8"))

    try:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as server:
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_FROM, [to_email], msg.as_string())
        print(f"✅ 验证码邮件已成功发送至 {to_email}")
    except Exception as e:
        print(f"❌ 邮件发送失败: {e}")