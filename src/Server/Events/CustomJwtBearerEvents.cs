using System;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using BlazorHero.CleanArchitecture.Server.Localization;
using BlazorHero.CleanArchitecture.Shared.Wrapper;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using StackExchange.Redis;

namespace BlazorHero.CleanArchitecture.Server.Events
{
    internal class CustomJwtBearerEvents : JwtBearerEvents
    {
        // private readonly IDistributedCache _distributedCache;
        private readonly IStringLocalizer<ServerCommonResources> _localizer;
        private readonly IConnectionMultiplexer _redis;
        private readonly ILogger<CustomJwtBearerEvents> _logger;

        public CustomJwtBearerEvents(
            // IDistributedCache distributedCache,
            IStringLocalizer<ServerCommonResources> localizer, ILogger<CustomJwtBearerEvents> logger, IConnectionMultiplexer redis)
        {
            // _distributedCache = distributedCache;
            _localizer = localizer;
            _logger = logger;
            _redis = redis;
        }

        public override Task AuthenticationFailed(AuthenticationFailedContext context)
        {
            base.AuthenticationFailed(context);
            if (context.Exception is SecurityTokenExpiredException)
            {
                context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                context.Response.ContentType = "application/json";
                var result = JsonConvert.SerializeObject(Result.Fail(_localizer["The Token is expired."]));
                return context.Response.WriteAsync(result);
            }
            else
            {
#if DEBUG
                context.NoResult();
                context.Response.StatusCode = (int)HttpStatusCode.InternalServerError;
                context.Response.ContentType = "text/plain";
                return context.Response.WriteAsync(context.Exception.ToString());
#else
                                c.Response.StatusCode = (int)HttpStatusCode.InternalServerError;
                                c.Response.ContentType = "application/json";
                                var result =
 JsonConvert.SerializeObject(Result.Fail(localizer["An unhandled error has occurred."]));
                                return c.Response.WriteAsync(result);
#endif
            }

            return Task.CompletedTask;
        }

        public override Task Forbidden(ForbiddenContext context)
        {
            base.Forbidden(context);
            context.Response.StatusCode = (int)HttpStatusCode.Forbidden;
            context.Response.ContentType = "application/json";
            var result =
                JsonConvert.SerializeObject(Result.Fail(_localizer["You are not authorized to access this resource."]));
            return context.Response.WriteAsync(result);
        }

        public override Task MessageReceived(MessageReceivedContext context)
        {
            return base.MessageReceived(context);
        }

        public override async Task TokenValidated(TokenValidatedContext context)
        {
            await base.TokenValidated(context);
            var token = context.SecurityToken as JwtSecurityToken;
            if (token != null)
            {
                var timeStamp = DateTimeOffset.Now.ToUnixTimeSeconds().ToString();
                // var bytes = Encoding.UTF8.GetBytes(timeStamp);
                // await _distributedCache.SetStringAsync(token.RawSignature, timeStamp);
                var db = _redis.GetDatabase();
                var ok = await db.StringSetAsync(token.RawSignature,timeStamp );
                var signature = await db.StringGetAsync(token.RawSignature);
                _logger.LogInformation($"Token signature: {signature}");
            }
            context.Success();
        }

        public override Task Challenge(JwtBearerChallengeContext context)
        {
            base.Challenge(context);
            context.HandleResponse();
            if (!context.Response.HasStarted)
            {
                context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                context.Response.ContentType = "application/json";
                var result = JsonConvert.SerializeObject(Result.Fail(_localizer["You are not Authorized."]));
                return context.Response.WriteAsync(result);
            }

            return Task.CompletedTask;
        }
    }
}