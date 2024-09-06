using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly ILogger<AuthController> _logger;
    private readonly APS _aps;

    public AuthController(ILogger<AuthController> logger, APS aps)
    {
        _logger = logger;
        _aps = aps;
    }

    public static async Task<Tokens> PrepareTokens(HttpRequest request, HttpResponse response, APS aps)
    {
        string token = "eyJhbGciOiJSUzI1NiIsImtpZCI6IlhrUFpfSmhoXzlTYzNZS01oRERBZFBWeFowOF9SUzI1NiIsInBpLmF0bSI6ImFzc2MifQ.eyJzY29wZSI6WyJkYXRhOnJlYWQiLCJkYXRhOndyaXRlIiwiYnVja2V0OnJlYWQiLCJidWNrZXQ6Y3JlYXRlIl0sImNsaWVudF9pZCI6IjU1OGs3OHZkUVE2alBiQktoTmVmR09ORnJHb1pqUUNyRVZENGVQWkQ4MFRqa2ZqSyIsImlzcyI6Imh0dHBzOi8vZGV2ZWxvcGVyLmFwaS5hdXRvZGVzay5jb20iLCJhdWQiOiJodHRwczovL2F1dG9kZXNrLmNvbSIsImp0aSI6InJOYWNQYVVqRDBBbUNwV2l4OTNWN1lzNkhMTGEwZGZVVEpOQkluZDN0OFRtYkUyT0oydHhiRGtEWHlLOWZPeXoiLCJleHAiOjE3MjU2NTQzMzl9.G89wqbKft-7CDjy9ZCy90AS3BBWUEBFjIeVl2cwHZ1dFUUkby9YqCBHMv65lI4MQd4cJ_tFbCXFgXELuk_nOJR_2sT8El1ilCGYD2WqwWk6lpRCColxy5LHAPbFTJGZjynIurUgSJ6gvyu6IL2OfG5c3-_9l_9PXMEHT2JtBDNFmLaDpYZ6HKpiToaxzIpDOmrzZQ54CL48ugprhZ4OieK5fzynkoHghvZ1Ib5QPPesffVoFnyJvQ8aKPPMNSxE7q2w5ArB4ImwRb1sBd8P-CbitUEEXFnBu7JL5eewGWgrzY9FLBQF1IRqKlCeWnyuf0nxXHQIu6RoYrNCUEF7aKg";
        var tokens = new Tokens
        {
            PublicToken = token,
            InternalToken = token,
            RefreshToken = token,
            ExpiresAt = DateTime.Parse("01-01-2025")
        };
        if (tokens.ExpiresAt < DateTime.Now.ToUniversalTime())
        {
            tokens = await aps.RefreshTokens(tokens);
            response.Cookies.Append("public_token", tokens.PublicToken);
            response.Cookies.Append("internal_token", tokens.InternalToken);
            response.Cookies.Append("refresh_token", tokens.RefreshToken);
            response.Cookies.Append("expires_at", tokens.ExpiresAt.ToString());
        }
        return tokens;
    }

    [HttpGet("login")]
    public ActionResult Login()
    {
        var redirectUri = _aps.GetAuthorizationURL();
        return Redirect(redirectUri);
    }

    [HttpGet("logout")]
    public ActionResult Logout()
    {
        Response.Cookies.Delete("public_token");
        Response.Cookies.Delete("internal_token");
        Response.Cookies.Delete("refresh_token");
        Response.Cookies.Delete("expires_at");
        return Redirect("/");
    }

    [HttpGet("callback")]
    public async Task<ActionResult> Callback(string code)
    {
        var tokens = await _aps.GenerateTokens(code);
        Response.Cookies.Append("public_token", tokens.PublicToken);
        Response.Cookies.Append("internal_token", tokens.InternalToken);
        Response.Cookies.Append("refresh_token", tokens.RefreshToken);
        Response.Cookies.Append("expires_at", tokens.ExpiresAt.ToString());
        return Redirect("/");
    }

    [HttpGet("profile")]
    public async Task<dynamic> GetProfile()
    {
        var tokens = await PrepareTokens(Request, Response, _aps);
        if (tokens == null)
        {
            return Unauthorized();
        }
        var profile = await _aps.GetUserProfile(tokens);
        return new
        {
            name = profile.Name
        };
    }

    [HttpGet("token")]
    public async Task<dynamic> GetPublicToken()
    {
        var tokens = await PrepareTokens(Request, Response, _aps);
        if (tokens == null)
        {
            return Unauthorized();
        }
        return new
        {
            access_token = tokens.PublicToken,
            token_type = "Bearer",
            expires_in = Math.Floor((tokens.ExpiresAt - DateTime.Now.ToUniversalTime()).TotalSeconds)
        };
    }
}
