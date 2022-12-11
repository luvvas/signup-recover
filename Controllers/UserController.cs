using Microsoft.EntityFrameworkCore;

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
    public async Task<ActionResult> Register(UserRegisterRequest request)
    {
      if (_context.Users.Any(u => u.Email == request.Email))
      {
        return BadRequest("User already exists");
      }

      CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);

      User newUser = new User
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

    [HttpPost("login")]
    public async Task<ActionResult> Login(UserLoginRequest request)
    {
      var dbUser = await _context.Users
        .FirstOrDefaultAsync(u => u.Email == request.Email);

      if (dbUser == null)
      {
        return BadRequest("User not found.");
      }

      if (!VerifyPasswordHash(request.Password, dbUser.PasswordHash, dbUser.PasswordSalt))
      {
        return BadRequest("Password is incorrect.");
      }

      if (dbUser.VerifiedAt == null)
      {
        return BadRequest("Not verified!");
      }

      return Ok($"Welcome back, {dbUser.Email}!");
    }

    [HttpPost("verify")]
    public async Task<ActionResult> Verify(string token)
    {
      var dbUser = await _context.Users
        .FirstOrDefaultAsync(u => u.VerificationToken == token);

      if (dbUser == null)
      {
        return BadRequest("Invalid token");
      }

      dbUser.VerifiedAt = DateTime.UtcNow;
      await _context.SaveChangesAsync();

      return Ok("User verified!");
    }

    private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
    {
      using (var hmac = new HMACSHA512())
      {
        passwordSalt = hmac.Key;
        passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
      }
    }

    private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
    {
      using (var hmac = new HMACSHA512(passwordSalt))
      {
        var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));

        return computedHash.SequenceEqual(passwordHash);
      }

    }
    private string CreateRandomToken()
    {
      return Convert.ToHexString(RandomNumberGenerator.GetBytes(64));
    }
  }
}