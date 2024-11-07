using System.Net.Mail;
using System.Net;

namespace WebApplication1.Services.Email;
public class EmailService(IConfiguration configuration) : IEmailService
{
    private readonly IConfiguration configuration = configuration;

    public async Task SendEmail(string recipientEmail, string subject, string body)
    {
        var senderEmail = configuration.GetValue<string>("EMAIL_CONFIG:EMAIL");
        var password = configuration.GetValue<string>("EMAIL_CONFIG:PASSWORD");
        var host = configuration.GetValue<string>("EMAIL_CONFIG:HOST");
        var port = configuration.GetValue<int>("EMAIL_CONFIG:PORT");

        var smtpClient = new SmtpClient(host, port);
        smtpClient.EnableSsl = true;
        smtpClient.UseDefaultCredentials = false;

        smtpClient.Credentials = new NetworkCredential(senderEmail, password);
        var message = new MailMessage(senderEmail!, recipientEmail, subject, body);
        await smtpClient.SendMailAsync(message);
    }
}

