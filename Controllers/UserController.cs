using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;

using signup_recover.Data;
using signup_recover.Models;

namespace signup_recover.Controllers
{
  [ApiController]
  [Route("api/[controller]")]
  public class UserController : ControllerBase
  {
    private readonly DataContext _context;
    public UserController(DataContext context)
    {
      _context = context;
    }

    [HttpPost("register")]
    public async Task<ActionResult<User>> Register(UserRegisterRequest request)
    {
      if (_context.Users.Any(u => u.Email == request.Email))
      {
        return BadRequest("User already exists");
      }

      CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);

      var newUser = new User
      {
        Email = request.Email,
        PasswordHash = passwordHash,
        PasswordSalt = passwordSalt,
        VerificationToken = CreateRandomToken()
      };

      _context.Users.Add(newUser);
      await _context.SaveChangesAsync();

      return Ok("User sucessfully created!");
    }

    private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
    {
      using (var hmac = new HMACSHA512())
      {
        passwordSalt = hmac.Key;
        passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
      }
    }

    private string CreateRandomToken()
    {
      return Convert.ToHexString(RandomNumberGenerator.GetBytes(64));
    }
  }
}