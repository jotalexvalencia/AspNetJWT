namespace AngularAuthAPI.Models
{
    public class EmailModel
    {
        public EmailModel(string to, string subject, string content)
        {
            To = to;
            Subject = subject;
            Content = content;
        }

        public string To { get; set; }
        public string Subject { get; set; }
        public string Content { get; set; }
    }
}
