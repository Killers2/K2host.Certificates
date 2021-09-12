/*
' /====================================================\
'| Developed Gabriel Calegari                           |
'| URL: https://github.com/gabrielcalegari              | 
'| Use: General                                         |
' \====================================================/
*/
using System.Net.Http;

namespace OcspResponder.Core.Extensions
{
    /// <summary>
    /// Extension methods for <see cref="HttpRequestMessage"/>
    /// </summary>
    public static class HttpRequestExtensions
    {
       
        /// <summary>
        /// Converts the <see cref="HttpRequestMessage"/> to <see cref="OcspHttpRequest"/>
        /// </summary>
        /// <param name="requestMessage"><see cref="HttpRequestMessage"/></param>
        /// <returns><see cref="OcspHttpRequest"/></returns>
        public static OcspHttpRequest ToOcspHttpRequest(this HttpRequestMessage requestMessage)
        {
            var httpRequestBase = new OcspHttpRequest
            {
                HttpMethod  = requestMessage.Method.Method,
                MediaType   = requestMessage.Content.Headers.ContentType.MediaType,
                RequestUri  = requestMessage.RequestUri,
                Content     = requestMessage.Content.ReadAsByteArrayAsync().Result
            };

            return httpRequestBase;
        }
    }
}