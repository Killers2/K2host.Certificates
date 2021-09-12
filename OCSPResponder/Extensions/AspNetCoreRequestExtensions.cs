/*
' /====================================================\
'| Developed Gabriel Calegari                           |
'| URL: https://github.com/gabrielcalegari              | 
'| Use: General                                         |
' \====================================================/
*/
using System;
using System.IO;
using System.Text;

using Microsoft.AspNetCore.Http;

using OcspResponder.Core;

namespace OcspResponder.AspNetCore
{
    /// <summary>
    /// Set of extension methods for <see cref="HttpRequest"/>
    /// </summary>
    public static class HttpRequestExtensions
    {

        private const string UnknownHostName = "UNKNOWN-HOST";

        /// <summary>
        /// Converts <see cref="HttpRequest"/> to <see cref="OcspHttpRequest"/>
        /// </summary>
        /// <param name="request"><see cref="HttpRequest"/></param>
        /// <returns><see cref="OcspHttpRequest"/></returns>
        public static OcspHttpRequest ToOcspHttpRequest(this HttpRequest request)
        {
            OcspHttpRequest ocspHttpRequest = new();
            ocspHttpRequest.HttpMethod      = request.Method;
            ocspHttpRequest.MediaType       = request.ContentType;
            ocspHttpRequest.RequestUri      = request.GetUri();
            ocspHttpRequest.Content         = request.GetRawBodyBytesAsync();

            return ocspHttpRequest;
        }

        /// <summary>
        /// Gets http request Uri from request object
        /// </summary>
        /// <param name="request">The <see cref="HttpRequest"/></param>
        /// <returns>A New Uri object representing request Uri</returns>
        private static Uri GetUri(this HttpRequest request)
        {
            if (null == request)
                throw new Exception("The request was null");

            if (true == string.IsNullOrWhiteSpace(request.Scheme))
                throw new ArgumentException("Http request Scheme is not specified");

            string hostName = request.Host.HasValue ? request.Host.ToString() : UnknownHostName;

            var builder = new StringBuilder();

            builder.Append(request.Scheme)
                .Append("://")
                .Append(hostName);

            if (true == request.Path.HasValue)
                builder.Append(request.Path.Value);

            if (true == request.QueryString.HasValue)
                builder.Append(request.QueryString);

            return new Uri(builder.ToString());
        }

        /// <summary>
        /// Retrieves the raw body as a byte array from the Request.Body stream
        /// </summary>
        /// <param name="request">The <see cref="HttpRequest"/></param>
        /// <returns></returns>
        private static byte[] GetRawBodyBytesAsync(this HttpRequest request)
        {
            using var ms = new MemoryStream();
            request.Body.CopyToAsync(ms);
            return ms.ToArray();
        }

    }
}