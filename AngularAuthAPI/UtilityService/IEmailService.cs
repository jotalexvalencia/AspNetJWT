using AngularAuthAPI.Models;

namespace AngularAuthAPI.UtilityService
{
    public interface IEmailService
    {
        void SendEmail(EmailModel emailModel);
    }
}
