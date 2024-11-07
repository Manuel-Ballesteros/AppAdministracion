namespace WebApplication1.Services.Email
{
    public interface IEmailService
    {
        Task SendEmail(string recipientEmail, string subject, string body);
    }
}