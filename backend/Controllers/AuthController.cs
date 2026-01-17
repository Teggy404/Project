using backend.Data;
using backend.Services;
using Microsoft.AspNetCore.Mvc;
using backend.Data;
using backend.Dtos;
using backend.Models;
using backend.Services;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.EntityFrameworkCore;

namespace backend.Controllers;

[ApiController]
[Route("auth")]
public class AuthController : ControllerBase
{
    private readonly AppDbContext _db;
    private readonly PasswordService _passwords;
    private readonly TokenService _tokens;

    public AuthController(AppDbContext db, PasswordService passwords, TokenService tokens)
    {
        _db = db;
        _passwords = passwords;
        _tokens = tokens;
    }

    [HttpPost("register")]
    public async Task<ActionResult<AuthRequest.AuthResponse>> Register(RegisterRequest req)
    {
        var email = req.Email.Trim().ToLower();

        var exists = await _db.Users.AnyAsync(u => u.Email == email);
        if (exists) return BadRequest("Email is already registered");

        var user = new User
        {
            Email = email,
            PasswordHash = _passwords.Hash(req.Password)
        };

        _db.Users.Add(user);
        await _db.SaveChangesAsync();

        var token = _tokens.CreateToken(user);
        return Ok(new AuthRequest.AuthResponse(token));
    }
    
    [HttpPost("login")]
    public async Task<ActionResult<AuthRequest.AuthResponse>> Login(LoginRequest req)
    {
        var email = req.Email.Trim().ToLower();
        
        var user = await _db.Users.SingleOrDefaultAsync(u => u.Email == email);
        if(user is null) return Unauthorized("Invalid credentials");

        var ok = _passwords.Verify(user.PasswordHash, req.Password);
        if(!ok) return Unauthorized("Invalid Credentials");

        var token = _tokens.CreateToken(user);
        return Ok(new AuthRequest.AuthResponse(token));
    }
}