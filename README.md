# Naext /nɛkst/

HTTP client library in C++.

Wraps native HTTP client functionality on macOS, Windows, Linux, iOS and Android in a single, simple non-blocking API.

### Acknowledgement

This work is based on the Naett library by Erik Agsjö.

## Using Naext

Add the files `naext.h` and `naext.cpp` to your project. Everything is inside the namespace `Naext`.

Initialise the library by calling Naext::Init(). On Android you need to provide a `JavaVM*` handle.
On other platforms use `nullptr`.

See `naext.h` for documentation comments.

## Platform implementations

Naext uses the following HTTP client libraries on each platform:

| Platform | Library / component | Build with |
| --- | --- | --- |
| macOS, iOS | NSURLRequest | -framework Foundation |
| Windows | WinHTTP Sessions | -lwinhttp |
| Android | java.net.URL | NDK |
| Linux | libcurl | -lcurl -lpthread |

### Example

```cpp
#include "naext.h"
#include <unistd.h>
#include <stdio.h>

int main(int argc, char** argv)
    {
    Naext::Init(nullptr);
    Naext::Request req("https://foo.site.net");
    req.AddHeader("Accept","application/json");
    req.SetMethod("GET");
    
    Naext::Response res = req.Send();
    while (!res.IsComplete())
        usleep(100 * 1000);
    
    int status = res.Status();
    if (status < 0)
        {
        printf("Request failed; status=%d.\n",status);
        return status;
        }

    std::string body = res.Body();
    printf("Received %d bytes of type '%s':\n",body.size(),res.Header("Content-Type"));
    printf("%.100s\n...\n",body.c_str());
    }
```
