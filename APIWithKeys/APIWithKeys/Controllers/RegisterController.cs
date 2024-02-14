using APIWithKeys.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Npgsql;
using System;
using System.Data;
using System.Data.SqlClient;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace APIWithKeys.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class RegisterController : ControllerBase
    {
        public static Users user = new Users();
        private readonly IConfiguration _configuration;

        public RegisterController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpPost]
        [Route("Register")]
        public IActionResult Register([FromBody] UserDTO usersdto)
        //public async Task<ActionResult<Users>> Register(UserDTO request)

        {
            //CreatePasswordHash(request.password, out byte[] passwordHash, out byte[] passwordSalt);
            //user.username = request.username;
            //user.userpasswordHash = passwordHash;
            //user.userpasswordSalt = passwordSalt;
            //return Ok(user);

            CreatePasswordHash(usersdto.password, out byte[] passwordHash, out byte[] passwordSalt);

            int result = 0;
            Guid id = Guid.NewGuid();
            string connect = _configuration["ConnectionStrings:postgres"];
            NpgsqlConnection con = new NpgsqlConnection(connect);
            StringBuilder query = new StringBuilder();
            query.Append("INSERT INTO users (userid, username, passwordhash, passwordsalt)");
            query.Append("VALUES (@userid, @username, @passwordhash, @passwordsalt)");
            NpgsqlCommand ncm = new NpgsqlCommand(query.ToString(), con);
            ncm.Parameters.Add("@userid", NpgsqlTypes.NpgsqlDbType.Uuid).Value = id;
            ncm.Parameters.Add("@username", NpgsqlTypes.NpgsqlDbType.Text).Value = usersdto.username.ToString();
            ncm.Parameters.Add("@passwordhash", NpgsqlTypes.NpgsqlDbType.Bytea).Value = passwordHash;
            ncm.Parameters.Add("@passwordsalt", NpgsqlTypes.NpgsqlDbType.Bytea).Value = passwordSalt;
            try
            {
                con.Open();
                result = ncm.ExecuteNonQuery();
                con.Close();
                return Ok(result);
            }
            catch (Exception ex)
            {
                con.Close();
                return BadRequest(ex.Message);
            }

        }
        //public IActionResult Register([FromBody] UserDTO usersdto)
        //{
        //    byte[] passwordHash, passwordSalt;
        //    CreatePasswordHash(usersdto.password, out passwordHash, out passwordSalt); // แก้ไขตรงนี้
        //    Guid id = Guid.NewGuid();
        //    string connect = _configuration["ConnectionStrings:postgres"];
        //    string query = "INSERT INTO users (userid, username, passwordhash, passwordsalt) VALUES (@userid, @username, @passwordhash, @passwordsalt)";

        //    using (NpgsqlConnection con = new NpgsqlConnection(connect))
        //    {

        //        using (NpgsqlCommand ncm = new NpgsqlCommand(query, con))
        //        {
        //            //ncm.Parameters.AddWithValue("@userid", id);
        //            //ncm.Parameters.AddWithValue("@username", usersdto.username);
        //            //ncm.Parameters.AddWithValue("@passwordhash", passwordHash);
        //            //ncm.Parameters.AddWithValue("@passwordsalt", passwordSalt);
        //            //    NpgsqlCommand ncm = new NpgsqlCommand(query.ToString(), con);
        //            ncm.Parameters.Add("@userid", NpgsqlTypes.NpgsqlDbType.Uuid).Value = id;
        //            ncm.Parameters.Add("@username", NpgsqlTypes.NpgsqlDbType.Text).Value = usersdto.username.ToString();
        //            ncm.Parameters.Add("@passwordhash", NpgsqlTypes.NpgsqlDbType.Bytea).Value = passwordHash;
        //            ncm.Parameters.Add("@passwordsalt", NpgsqlTypes.NpgsqlDbType.Bytea).Value = passwordSalt;

        //            try
        //            {
        //                con.Open();
        //                int result = ncm.ExecuteNonQuery();
        //                return Ok(result);
        //            }
        //            catch (Exception ex)
        //            {
        //                return BadRequest(ex.Message);
        //            }
        //        }
        //    }
        //}

        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }


        [HttpPost]
        [Route("login")]
        public IActionResult Login(UserDTO request)
        {
            Users user = new Users();
            string token = "";
            string connect = _configuration["ConnectionStrings:postgres"];
            NpgsqlConnection con = new NpgsqlConnection(connect);
            StringBuilder query = new StringBuilder();
            query.Append("SELECT * FROM users WHERE username = @username");
            NpgsqlCommand cm = new NpgsqlCommand(query.ToString(), con);
            cm.Parameters.Add("@username", NpgsqlTypes.NpgsqlDbType.Text).Value = request.username;
            try
            {
                con.Open();
                NpgsqlDataReader reader = cm.ExecuteReader();
                if (reader.HasRows)
                {
                    if (reader.Read())
                    {
                        string username = reader["username"].ToString();
                        byte[] passwordHashBytes = reader.GetFieldValue<byte[]>("passwordhash");
                        byte[] passwordSaltBytes = reader.GetFieldValue<byte[]>("passwordsalt");
                        if (VerifyPasswordHash(request.password, passwordHashBytes, passwordSaltBytes))
                        {
                            user.username = username;
                            user.userpasswordHash = passwordHashBytes;
                            user.userpasswordSalt = passwordSaltBytes;
                            token = CreateToken(user);
                        }
                    }

                    return Ok(token);
                }
                else
                {
                    return NotFound();
                }
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
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


        private string CreateToken(Users user)
        {
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.username)
            };

            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(_configuration.GetSection("AppSettings:Token").Value.PadRight(32)));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature);

            var token = new JwtSecurityToken(
            claims: claims,
            expires: DateTime.Now.AddDays(1),
            signingCredentials: creds);
            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }



    }
}
