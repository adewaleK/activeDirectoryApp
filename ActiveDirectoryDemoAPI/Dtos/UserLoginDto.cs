namespace ActiveDirectoryDemoAPI.Dtos
{ 
    public record UserLoginDto
    {
        public string Email { get; set; }
        public string Password { get; set; }

    }
    public record AuthDto
    {
        public string AccessToken { get; set; }
        public DateTime? ExpiresIn { get; set; }
        public string RefreshToken { get; set; }
    }
}
