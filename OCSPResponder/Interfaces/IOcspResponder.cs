/*
' /====================================================\
'| Developed Gabriel Calegari                           |
'| URL: https://github.com/gabrielcalegari              | 
'| Use: General                                         |
' \====================================================/
*/
namespace OcspResponder.Core
{
    public interface IOcspResponder
    {
        OcspHttpResponse Respond(OcspHttpRequest httpRequest);
    }
}