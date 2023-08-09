/*
naext.cpp

Copyright (C) 2023 CartoType Ltd.
See www.cartotype.com for more information.

Naext: a simple HTTP client library in C++.
Based on the Naett library.
*/

/*
MIT License

Naext library (this software) Copyright (C) 2023 CartoType Ltd.
Naett library, on which this software is based, Copyright (C) 2021 Erik Agsjö.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include "naext.h"

#include <string>
#include <map>
#include <vector>
#include <array>
#include <algorithm>
#include <cstring>
#include <cassert>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>

#define __WINDOWS__ 1
#undef min
#endif

#if __linux__ && !__ANDROID__
#define __LINUX__ 1
#include <curl/curl.h>
#include <curl/curl.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#endif

#if __ANDROID__
#include <jni.h>
#include <pthread.h>

#include <stdlib.h>
#include <string.h>
#include <jni.h>
#include <android/log.h>
#include <pthread.h>
#include <stdarg.h>

#ifndef NDEBUG
#define LOGD(...) ((void)__android_log_print(ANDROID_LOG_DEBUG, "naext", __VA_ARGS__))
#else
#define LOGD(...) ((void)0)
#endif
#define LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, "naext", __VA_ARGS__))
#define LOGE(...) ((void)__android_log_print(ANDROID_LOG_ERROR, "naext", __VA_ARGS__))

static JavaVM* globalVM = nullptr;

JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved)
    {
    globalVM = vm;
    return JNI_VERSION_1_2;
    }

#endif

#ifdef __APPLE__

#include "TargetConditionals.h"
#include <objc/objc.h>
#include <math.h>

#include <objc/NSObjCRuntime.h>
#include <objc/message.h>
#include <objc/runtime.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#if TARGET_OS_IPHONE
#define __IOS__ 1
#else
#define __MACOS__ 1
#endif

#endif

namespace Naext
    {

    class RequestInternal
        {
        public:
        RequestInternal();

        ~RequestInternal();

        size_t StandardReadFunc(void* aDest,size_t aBufferSize);

        void PlatformOpen();

        void PlatformClose();

        bool m_platform_open = false;
        std::string m_url;
        std::string m_method = "GET";
        int m_timeout_in_milliseconds = 500;
        ReadFunc m_body_reader = nullptr;
        WriteFunc m_body_writer = nullptr;
        std::map<std::string, std::string> m_headers;
        std::string m_body;
        size_t m_body_position = 0;

#if __APPLE__
        id m_url_request = nullptr;
#endif
#if __ANDROID__
        jobject m_url_object = nullptr;
#endif
#if __WINDOWS__
        HINTERNET m_session = nullptr;
        HINTERNET m_connection = nullptr;
        HINTERNET m_request = nullptr;
        std::wstring m_host;
        std::wstring m_resource;
#endif
        };

    class ResponseInternal
        {
        public:
        ResponseInternal(std::shared_ptr<RequestInternal> aRequest);

        ~ResponseInternal();

        size_t StandardWriteFunc(const void* aSource,size_t aBytes);

        std::shared_ptr<RequestInternal> m_request;
        int m_code = 0;
        bool m_complete = false;
        std::map<std::string, std::string> m_headers;
        WriteFunc m_body_writer = nullptr;
        std::string m_body;
#if __APPLE__
        id m_session = nullptr;
#endif
#if __ANDROID__
        void ProcessRequest();
        pthread_t m_worker_thread = 0;
        bool m_close_requested = false;
#endif
#if __LINUX__
        struct curl_slist* m_header_list = nullptr;
#endif
#if __WINDOWS__
        std::array<uint8_t,10240> m_buffer = {  };
        size_t m_bytes_left = 0;
#endif
        };

    void PlatformInit(InitData aInitData);

    static bool initialised = false;

    void Init(InitData aInitData)
        {
        assert(!initialised);
        PlatformInit(aInitData);
        initialised = true;
        }

    Request::Request(const char* aUrl):
            m_internal(std::make_shared<RequestInternal>())
        {
        assert(initialised);
        m_internal->m_url = aUrl;
        AddHeader("User-Agent","Naext");
        }

    Request::Request(std::shared_ptr<RequestInternal> aInternal):
            m_internal(aInternal)
        {
        }

    Request::~Request()
        {
        }

    void Request::SetMethod(const char* aMethod)
        {
        m_internal->m_method = aMethod;
        }

    std::string LowerCase(const char* aText)
        {
        std::string s = aText;
        std::transform(s.begin(), s.end(), s.begin(), [](char c)
            {
            if (c >= 'A' && c <= 'Z') c += 32;
            return c;
            });
        return s;
        }

    void Request::AddHeader(const char* aName,const char* aValue)
        {
        assert(aName);
        assert(aValue);
        m_internal->m_headers[LowerCase(aName)] = aValue;
        }

    void Request::SetBody(const char* aBody,int aSize)
        {
        m_internal->m_body.assign(aBody, aSize);
        m_internal->m_body_reader = [this](void* aDest,size_t aBufferSize)->size_t
            { return m_internal->StandardReadFunc(aDest,aBufferSize); };
        }

    void Request::SetBody(ReadFunc aReader)
        {
        m_internal->m_body_reader = aReader;
        m_internal->m_body.clear();
        }

    void Request::SetResponseBodyWriter(WriteFunc aWriter)
        {
        m_internal->m_body_writer = aWriter;
        }

    void Request::SetTimeout(int aMilliseconds)
        {
        m_internal->m_timeout_in_milliseconds = aMilliseconds;
        }

    Response Request::Send()
        {
        assert(initialised);
        m_internal->PlatformOpen();
        auto r = std::make_shared<ResponseInternal>(m_internal);
        return Response(r);
        }

    Response::Response(std::shared_ptr<ResponseInternal> aInternal) :
            m_internal(aInternal)
        {
        }

    const std::string& Response::Body()
        {
        return m_internal->m_body;
        }

    const char* Response::Header(const char* aName)
        {
        assert(aName);
        auto iter = m_internal->m_headers.find(LowerCase(aName));
        if (iter == m_internal->m_headers.end())
            return nullptr;
        return iter->second.c_str();
        }

    void Response::ListHeaders(HeaderLister aLister)
        {
        if (!aLister)
            return;
        for (const auto &p : m_internal->m_headers)
            {
            if (aLister(p.first.c_str(), p.second.c_str()))
                break;
            }
        }

    Naext::Request Response::Request()
        {
        return Naext::Request(m_internal->m_request);
        }

    bool Response::IsComplete()
        {
        return m_internal->m_complete;
        }

    int Response::Status()
        {
        return m_internal->m_code;
        }

    RequestInternal::RequestInternal()
        {
        m_body_reader = [this](void* aDest,size_t aBufferSize)->size_t
            { return StandardReadFunc(aDest,aBufferSize); };
        }

    RequestInternal::~RequestInternal()
        {
        PlatformClose();
        }

    size_t RequestInternal::StandardReadFunc(void* aDest,size_t aBufferSize)
        {
        if (aDest == nullptr)
            return m_body.size();
        size_t bytes_to_read = m_body.size() - m_body_position;
        if (bytes_to_read > aBufferSize)
            bytes_to_read = aBufferSize;
        const char *source = &m_body[m_body_position];
        memcpy(aDest, source, bytes_to_read);
        m_body_position += bytes_to_read;
        return bytes_to_read;
        }

    size_t ResponseInternal::StandardWriteFunc(const void* aSource,size_t aBytes)
        {
        size_t n = m_body.size();
        m_body.resize(n + aBytes);
        memcpy(&m_body[n], aSource, aBytes);
        return aBytes;
        }

#ifdef __APPLE__

#if defined(__OBJC__) && __has_feature(objc_arc)
#error "ARC is not supported"
#endif

    // ABI is a bit different between platforms
#ifdef __arm64__
#define abi_objc_msgSend_stret objc_msgSend
#else
#define abi_objc_msgSend_stret objc_msgSend_stret
#endif
#ifdef __i386__
#define abi_objc_msgSend_fpret objc_msgSend_fpret
#else
#define abi_objc_msgSend_fpret objc_msgSend
#endif

#define objc_msgSendSuper_t(RET, ...) ((RET(*)(struct objc_super*, SEL, ##__VA_ARGS__))objc_msgSendSuper)
#define objc_msgSend_t(RET, ...) ((RET(*)(id, SEL, ##__VA_ARGS__))objc_msgSend)
#define objc_msgSend_stret_t(RET, ...) ((RET(*)(id, SEL, ##__VA_ARGS__))abi_objc_msgSend_stret)
#define objc_msgSend_id objc_msgSend_t(id)
#define objc_msgSend_void objc_msgSend_t(void)
#define objc_msgSend_void_id objc_msgSend_t(void, id)
#define objc_msgSend_void_bool objc_msgSend_t(void, bool)

#define sel(NAME) sel_registerName(NAME)
#define class(NAME) ((id)objc_getClass(NAME))
#define makeClass(NAME, SUPER) \
    objc_allocateClassPair((Class)objc_getClass(SUPER), NAME, 0)

    // Check here to get the signature right:
    // https://nshipster.com/type-encodings/
    // https://ko9.org/posts/encode-types/
#define addMethod(CLASS, NAME, IMPL, SIGNATURE) \
    if (!class_addMethod(CLASS, sel(NAME), (IMP) (IMPL), (SIGNATURE))) assert(false)

#define addIvar(CLASS, NAME, SIZE, SIGNATURE) \
    if (!class_addIvar(CLASS, NAME, SIZE, rint(log2(SIZE)), SIGNATURE)) assert(false)

#define objc_alloc(CLASS) objc_msgSend_id(class(CLASS), sel("alloc"))
#define autorelease(OBJ) objc_msgSend_void(OBJ, sel("autorelease"))
#define retain(OBJ) objc_msgSend_void(OBJ, sel("retain"))
#define release(OBJ) objc_msgSend_void(OBJ, sel("release"))

#if __LP64__ || NS_BUILD_32_LIKE_64
#define NSIntegerEncoding "q"
#define NSUIntegerEncoding "L"
#else
#define NSIntegerEncoding "i"
#define NSUIntegerEncoding "I"
#endif

#ifdef DEBUG
    static void _showPools(const char* context) {
        fprintf(stderr, "NSAutoreleasePool@%s:\n", context);
        objc_msgSend_void(class("NSAutoreleasePool"), sel("showPools"));
    }
#define showPools(x) _showPools((x))
#else
#define showPools(x)
#endif

    static id pool()
        {
        return objc_msgSend_id(objc_alloc("NSAutoReleasePool"), sel("init"));
        }

    void PlatformInit(InitData aInitData)
        {
        }

    id NSString(const char* string)
        {
        return objc_msgSend_t(id, const char*)(class("NSString"), sel("stringWithUTF8String:"), string);
        }

    void RequestInternal::PlatformOpen()
        {
        id p = pool();

        id urlString = NSString(m_url.c_str());
        id url = objc_msgSend_t(id, id)(class("NSURL"), sel("URLWithString:"), urlString);
        id request = objc_msgSend_t(id, id)(class("NSMutableURLRequest"), sel("requestWithURL:"), url);

        objc_msgSend_t(void, double)(request, sel("setTimeoutInterval:"), (double)(m_timeout_in_milliseconds) / 1000.0);
        id methodString = NSString(m_method.c_str());
        objc_msgSend_t(void, id)(request, sel("setHTTPMethod:"), methodString);

        for (const auto& header: m_headers)
            {
            id name = NSString(header.first.c_str());
            id value = NSString(header.second.c_str());
            objc_msgSend_t(void, id, id)(request, sel("setValue:forHTTPHeaderField:"), value, name);
            }

        char byteBuffer[10240];
        int bytesRead = 0;

        if (m_body_reader)
            {
            id bodyData = objc_msgSend_t(id, NSUInteger)(class("NSMutableData"), sel("dataWithCapacity:"), sizeof(byteBuffer));
            int totalBytesRead = 0;
            do
                {
                bytesRead = int(m_body_reader(byteBuffer,sizeof(byteBuffer)));
                totalBytesRead += bytesRead;
                objc_msgSend_t(void, const void*, NSUInteger)(bodyData, sel("appendBytes:length:"), byteBuffer, bytesRead);
                } while (bytesRead > 0);

            if (totalBytesRead > 0)
                objc_msgSend_t(void, id)(request, sel("setHTTPBody:"), bodyData);
            }

        retain(request);
        m_url_request = request;

        release(p);
        m_platform_open = true;
        }

    void didReceiveData(id self, SEL _sel, id session, id dataTask, id data)
        {
        ResponseInternal* res = nullptr;
        id p = pool();

        object_getInstanceVariable(self, "response", (void**)&res);

        if (res->m_headers.empty())
            {
            id response = objc_msgSend_t(id)(dataTask, sel("response"));
            res->m_code = int(objc_msgSend_t(NSInteger)(response, sel("statusCode")));
            id allHeaders = objc_msgSend_t(id)(response, sel("allHeaderFields"));

            NSUInteger headerCount = objc_msgSend_t(NSUInteger)(allHeaders, sel("count"));
            id headerNames[headerCount];
            id headerValues[headerCount];
            objc_msgSend_t(NSInteger, id*, id*, NSUInteger)(allHeaders, sel("getObjects:andKeys:count:"), headerValues, headerNames, headerCount);

            for (int i = 0; i < headerCount; i++)
                {
                const char* key = objc_msgSend_t(const char*)(headerNames[i], sel("UTF8String"));
                const char* value = objc_msgSend_t(const char*)(headerValues[i], sel("UTF8String"));
                res->m_headers[key] = value;
                }
            }

        const void* bytes = objc_msgSend_t(const void*)(data, sel("bytes"));
        NSUInteger length = objc_msgSend_t(NSUInteger)(data, sel("length"));
        res->m_body_writer(bytes,length);

        release(p);
        }

    static void didComplete(id self, SEL _sel, id session, id dataTask, id error)
        {
        ResponseInternal* res = nullptr;
        object_getInstanceVariable(self, "response", (void**)&res);

        if (error != nil)
            res->m_code = ConnectionError;
        res->m_complete = true;
        }

    static id createDelegate()
        {
        Class TaskDelegateClass = nil;

        if (!TaskDelegateClass)
            {
            TaskDelegateClass = objc_allocateClassPair((Class)objc_getClass("NSObject"), "NaextTaskDelegate", 0);
            class_addProtocol(TaskDelegateClass, objc_getProtocol("NSURLSessionDataDelegate"));

            addMethod(TaskDelegateClass, "URLSession:dataTask:didReceiveData:", didReceiveData, "v@:@@@");
            addMethod(TaskDelegateClass, "URLSession:task:didCompleteWithError:", didComplete, "v@:@@@");
            addIvar(TaskDelegateClass, "response", sizeof(void*), "^v");
            }

        id delegate = objc_msgSend_id((id)TaskDelegateClass, sel("alloc"));
        delegate = objc_msgSend_id(delegate, sel("init"));
        autorelease(delegate);

        return delegate;
        }

    ResponseInternal::ResponseInternal(std::shared_ptr<RequestInternal> aRequest):
        m_request(aRequest)
        {
        m_body_writer = aRequest->m_body_writer;
        if (m_body_writer == nullptr)
            m_body_writer = [this](const void* aSource,size_t aBytes)->size_t { return StandardWriteFunc(aSource,aBytes); };

        if (!aRequest->m_platform_open)
            {
            m_code = ConnectionError;
            m_complete = true;
            return;
            }

        id p = pool();
        id config = objc_msgSend_id(class("NSURLSessionConfiguration"), sel("ephemeralSessionConfiguration"));
        id delegate = createDelegate();
        id session = objc_msgSend_t(id, id, id, id)(class("NSURLSession"), sel("sessionWithConfiguration:delegate:delegateQueue:"), config, delegate, nil);
        retain(session);
        m_session = session;
        id task = objc_msgSend_t(id, id)(session, sel("dataTaskWithRequest:"), aRequest->m_url_request);
        object_setInstanceVariable(delegate, "response", (void*)this);
        objc_msgSend_void(task, sel("resume"));
        release(p);
        }

    void RequestInternal::PlatformClose()
        {
        release(m_url_request);
        m_url_request = nil;
        }

    ResponseInternal::~ResponseInternal()
        {
        release(m_session);
        }

#endif  // __APPLE__

#if __linux__ && !__ANDROID__

    static pthread_t workerThread;
    static int handleReadFD = 0;
    static int handleWriteFD = 0;

    static void panic(const char *message)
        {
        fprintf(stderr, "%s\n", message);
        exit(1);
        }

    static void *curlWorker(void *data)
        {
        CURLM* mc = (CURLM*)data;
        int activeHandles = 0;
        int messagesLeft = 1;

        struct curl_waitfd readFd = { handleReadFD, CURL_WAIT_POLLIN };

        union
            {
            CURL *handle;
            char buf[sizeof(CURL *)];
            } newHandle;

        int newHandlePos = 0;

        for (;;)
            {
            int status = curl_multi_perform(mc, &activeHandles);
            if (status != CURLM_OK)
                {
                panic("CURL processing failure");
                }

            int readyFDs = 0;
            curl_multi_wait(mc, &readFd, 1, 1000, &readyFDs);

            if (readyFDs == 0)
                {
                usleep(100 * 1000);
                }

            int bytesRead = read(handleReadFD, newHandle.buf, sizeof(newHandle.buf) - newHandlePos);
            if (bytesRead > 0)
                {
                newHandlePos += bytesRead;
                }
            if (newHandlePos == sizeof(newHandle.buf))
                {
                curl_multi_add_handle(mc, newHandle.handle);
                newHandlePos = 0;
                }

            struct CURLMsg* message = curl_multi_info_read(mc, &messagesLeft);
            if (message && message->msg == CURLMSG_DONE)
                {
                CURL* handle = message->easy_handle;
                ResponseInternal* res = nullptr;
                curl_easy_getinfo(handle, CURLINFO_PRIVATE, (char **)&res);
                curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &res->m_code);
                res->m_complete = true;
                curl_easy_cleanup(handle);
                }
            }

        return nullptr;
        }

    void PlatformInit(InitData /*aInitData*/)
        {
        curl_global_init(CURL_GLOBAL_ALL);
        CURLM *mc = curl_multi_init();
        int fds[2];
        if (pipe(fds) != 0)
            {
            panic("Failed to open pipe");
            }
        handleReadFD = fds[0];
        handleWriteFD = fds[1];

        int flags = fcntl(handleReadFD, F_GETFL, 0);
        fcntl(handleReadFD, F_SETFL, flags | O_NONBLOCK);

        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        pthread_create(&workerThread, &attr, curlWorker, mc);
        }

    void RequestInternal::PlatformOpen()
        {
        m_platform_open = true;
        }

    void RequestInternal::PlatformClose()
        {
        }

    static size_t readCallback(char* buffer, size_t size, size_t numItems, void* userData)
        {
        auto res = (ResponseInternal*)userData;
        return res->m_request->m_body_reader(buffer,size * numItems);
        }

    static size_t writeCallback(char* ptr, size_t size, size_t numItems, void* userData)
        {
        auto res = (ResponseInternal*)userData;
        return res->m_body_writer(ptr,size * numItems);
        }

#define METHOD(A, B, C) (((A) << 16) | ((B) << 8) | (C))

    static void setupMethod(CURL *curl, const char *method)
        {
        if (strlen(method) < 3)
            {
            return;
            }

        int methodCode = (method[0] << 16) | (method[1] << 8) | method[2];

        switch (methodCode)
            {
            case METHOD('G', 'E', 'T'):
            case METHOD('C', 'O', 'N'):
            case METHOD('O', 'P', 'T'):
                curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
                break;
            case METHOD('P', 'O', 'S'):
            case METHOD('P', 'A', 'T'):
            case METHOD('D', 'E', 'L'):
                curl_easy_setopt(curl, CURLOPT_POST, 1);
                break;
            case METHOD('P', 'U', 'T'):
                curl_easy_setopt(curl, CURLOPT_UPLOAD, 1);
                break;
            case METHOD('H', 'E', 'A'):
            case METHOD('T', 'R', 'A'):
                curl_easy_setopt(curl, CURLOPT_NOBODY, 1);
                break;
            }

        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
        }

    static size_t headerCallback(char* buffer, size_t size, size_t nitems, void* userData)
        {
        auto res = (ResponseInternal*)userData;
        const char* p = buffer;
        const char* end = buffer + size * nitems;

        while (p < end && *p == ' ')
            p++;
        auto name_start = p;
        while (p < end && *p != ':')
            p++;
        std::string name(name_start,p - name_start);
        if (p < end)
            p++;
        while (p < end && *p == ' ')
            p++;
        auto value_start = p;
        while (p < end && *p != 10 && *p != 13)
            p++;
        std::string value(value_start,p - value_start);
        if (name.size() && value.size())
            res->m_headers[name] = value;

        return size * nitems;
        }

    ResponseInternal::ResponseInternal(std::shared_ptr<RequestInternal> aRequest):
        m_request(aRequest)
        {
        m_body_writer = aRequest->m_body_writer;
        if (m_body_writer == nullptr)
            m_body_writer = [this](const void* aSource,size_t aBytes)->size_t { return StandardWriteFunc(aSource,aBytes); };

        if (!aRequest->m_platform_open)
            {
            m_code = ConnectionError;
            m_complete = true;
            return;
            }

        CURL* c = curl_easy_init();
        curl_easy_setopt(c, CURLOPT_URL, aRequest->m_url.c_str());
        curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT_MS, aRequest->m_timeout_in_milliseconds);

        curl_easy_setopt(c, CURLOPT_READFUNCTION, readCallback);
        curl_easy_setopt(c, CURLOPT_READDATA, this);

        curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, writeCallback);
        curl_easy_setopt(c, CURLOPT_WRITEDATA, this);

        curl_easy_setopt(c, CURLOPT_HEADERFUNCTION, headerCallback);
        curl_easy_setopt(c, CURLOPT_HEADERDATA, this);

        curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1);

        int bodySize = m_request->m_body_reader(nullptr,0);
        curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE, bodySize);

        setupMethod(c, aRequest->m_method.c_str());

        for (const auto& p : aRequest->m_headers)
            {
            std::string header = p.first + ':' + p.second;
            m_header_list = curl_slist_append(m_header_list,header.c_str());
            }
        curl_easy_setopt(c, CURLOPT_HTTPHEADER, m_header_list);

        curl_easy_setopt(c, CURLOPT_PRIVATE, this);
        write(handleWriteFD, &c, sizeof(c));
        }

    ResponseInternal::~ResponseInternal()
        {
        curl_slist_free_all(m_header_list);
        }

#endif

#ifdef __WINDOWS__

    void PlatformInit(InitData /*aInitData*/)
        {
        }

    std::string WinToUTF8(const wchar_t* aSource)
        {
        int length = WideCharToMultiByte(CP_UTF8,0,aSource,-1,nullptr,0,nullptr,nullptr);
        std::string s(length,0);
        int result = WideCharToMultiByte(CP_UTF8,0,aSource,-1,&s[0],length,nullptr,nullptr);
        if (!result)
            s.clear();
        return s;
        }

    std::wstring WinFromUTF8(const char* aSource)
        {
        int length = MultiByteToWideChar(CP_UTF8,0,aSource,-1,nullptr,0);
        std::wstring s(length,0);
        int result = MultiByteToWideChar(CP_UTF8,0,aSource,-1,&s[0],length);
        if (!result)
            s.clear();
        return s;
        }

    std::wstring PackHeaders(const RequestInternal& aRequest)
        {
        std::string s;
        for (const auto& p : aRequest.m_headers)
            {
            if (!s.empty())
                s += "\r\n";
            s += p.first;
            s += ':';
            s += p.second;
            }
        return WinFromUTF8(s.c_str());
        }

    void UnpackHeaders(ResponseInternal& aResponse,const std::wstring& aPacked)
        {
        auto h = WinToUTF8(aPacked.c_str());
        char* key = &h[0];
        aResponse.m_headers.clear();
        std::map<std::string,std::string> headers;
        for (;;)
            {
            size_t length = strlen(key);
            if (length == 0)
                break;
            char* value = strchr(key,':');
            if (value)
                {
                *value++ = 0;
                while (*value == ' ')
                    value++;
                aResponse.m_headers[LowerCase(key)] = value;
                }
            key += length + 1;
            }
        }

    static void callback(HINTERNET aRequest,
                         DWORD_PTR aContext,
                         DWORD aStatus,
                         LPVOID aStatusInformation,
                         DWORD aStatusInfoLength)
        {
        ResponseInternal* res = (ResponseInternal*)aContext;

        switch (aStatus)
            {
            case WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE:
                {
                DWORD buffer_size = 0;
                WinHttpQueryHeaders(aRequest,
                                    WINHTTP_QUERY_RAW_HEADERS,
                                    WINHTTP_HEADER_NAME_BY_INDEX,
                                    nullptr,
                                    &buffer_size,
                                    WINHTTP_NO_HEADER_INDEX);

                std::basic_string<wchar_t> buffer(buffer_size,0);
                WinHttpQueryHeaders(aRequest,
                                    WINHTTP_QUERY_RAW_HEADERS,
                                    WINHTTP_HEADER_NAME_BY_INDEX,
                                    &buffer[0],
                                    &buffer_size,
                                    WINHTTP_NO_HEADER_INDEX);
                UnpackHeaders(*res,buffer);

                DWORD status_code = 0;
                DWORD status_code_size = sizeof(status_code);
                WinHttpQueryHeaders(aRequest,
                                    WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                    WINHTTP_HEADER_NAME_BY_INDEX,
                                    &status_code,
                                    &status_code_size,
                                    WINHTTP_NO_HEADER_INDEX);
                res->m_code = status_code;

                if (!WinHttpQueryDataAvailable(aRequest,nullptr))
                    {
                    res->m_code = ProtocolError;
                    res->m_complete = true;
                    }
                }
                break;

            case WINHTTP_CALLBACK_STATUS_DATA_AVAILABLE:
                {
                DWORD* available = (DWORD*)aStatusInformation;
                res->m_bytes_left = *available;
                if (res->m_bytes_left == 0)
                    {
                    res->m_complete = true;
                    break;
                    }

                size_t bytes_to_read = std::min(res->m_bytes_left,res->m_buffer.size());
                if (!WinHttpReadData(aRequest,&res->m_buffer[0],DWORD(bytes_to_read),nullptr))
                    {
                    res->m_code = ReadError;
                    res->m_complete = true;
                    }
                }
                break;

            case WINHTTP_CALLBACK_STATUS_READ_COMPLETE:
                {
                size_t bytes_read = aStatusInfoLength;

                if (res->m_body_writer(&res->m_buffer[0],bytes_read) != bytes_read)
                    {
                    res->m_code = ReadError;
                    res->m_complete = true;
                    }

                res->m_bytes_left -= bytes_read;
                if (res->m_bytes_left > 0)
                    {
                    size_t bytes_to_read = std::min(res->m_bytes_left,res->m_buffer.size());
                    if (!WinHttpReadData(aRequest,&res->m_buffer[0],DWORD(bytes_to_read),nullptr))
                        {
                        res->m_code = ReadError;
                        res->m_complete = true;
                        }
                    }
                else if (!WinHttpQueryDataAvailable(aRequest,nullptr))
                    {
                    res->m_code = ProtocolError;
                    res->m_complete = true;
                    }
                }
                break;

            case WINHTTP_CALLBACK_STATUS_WRITE_COMPLETE:
            case WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE:
                {
                RequestInternal& req = *res->m_request;
                size_t bytes_read = req.m_body_reader(&res->m_buffer[0],res->m_buffer.size());
                if (bytes_read)
                    WinHttpWriteData(aRequest,&res->m_buffer[0],DWORD(bytes_read),nullptr);
                else if (!WinHttpReceiveResponse(aRequest,nullptr))
                    {
                    res->m_code = ReadError;
                    res->m_complete = true;
                    }
                }
                break;

            case WINHTTP_CALLBACK_STATUS_REQUEST_ERROR:
                {
                WINHTTP_ASYNC_RESULT* result = (WINHTTP_ASYNC_RESULT*)aStatusInformation;
                switch (result->dwResult)
                    {
                    case API_RECEIVE_RESPONSE:
                    case API_QUERY_DATA_AVAILABLE:
                    case API_READ_DATA:
                        res->m_code = ReadError;
                        break;
                    case API_WRITE_DATA:
                        res->m_code = WriteError;
                        break;
                    case API_SEND_REQUEST:
                        res->m_code = ConnectionError;
                        break;
                    default:
                        res->m_code = GenericError;
                    }

                res->m_complete = true;
                }
                break;
            }
        }

    void RequestInternal::PlatformOpen()
        {
        if (m_platform_open)
            return;

        auto url = WinFromUTF8(m_url.c_str());
        URL_COMPONENTS components;
        ZeroMemory(&components,sizeof(components));
        components.dwStructSize = sizeof(components);
        components.dwSchemeLength = (DWORD)-1;
        components.dwHostNameLength = (DWORD)-1;
        components.dwUrlPathLength = (DWORD)-1;
        components.dwExtraInfoLength = (DWORD)-1;
        bool cracked = WinHttpCrackUrl(url.c_str(),0,0,&components);
        if (!cracked)
            return;

        m_host.assign(components.lpszHostName,components.dwHostNameLength);
        m_resource.assign(components.lpszUrlPath,components.dwUrlPathLength + components.dwExtraInfoLength);
        m_session = WinHttpOpen(L"Naext",WINHTTP_ACCESS_TYPE_NO_PROXY,WINHTTP_NO_PROXY_NAME,WINHTTP_NO_PROXY_BYPASS,WINHTTP_FLAG_ASYNC);
        if (!m_session)
            {
            PlatformClose();
            return;
            }

        WinHttpSetStatusCallback(m_session,callback,WINHTTP_CALLBACK_FLAG_ALL_COMPLETIONS,0);
        m_connection = WinHttpConnect(m_session,m_host.c_str(),components.nPort,0);
        if (!m_connection)
            {
            PlatformClose();
            return;
            }

        auto verb = WinFromUTF8(m_method.c_str());
        m_request = WinHttpOpenRequest(m_connection,
                                       verb.c_str(),
                                       m_resource.c_str(),
                                       nullptr,
                                       WINHTTP_NO_REFERER,
                                       WINHTTP_DEFAULT_ACCEPT_TYPES,
                                       components.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0);
        if (!m_request)
            {
            PlatformClose();
            return;
            }

        auto headers = PackHeaders(*this);
        if (!headers.empty())
            {
            if (!WinHttpAddRequestHeaders(m_request,headers.c_str(),DWORD(headers.length()),WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE))
                {
                PlatformClose();
                return;
                }
            }

        m_platform_open = true;
        }

    void RequestInternal::PlatformClose()
        {
        if (m_request)
            WinHttpCloseHandle(m_request);
        if (m_connection)
            WinHttpCloseHandle(m_connection);
        if (m_session)
            WinHttpCloseHandle(m_session);
        m_platform_open = false;
        }

    ResponseInternal::ResponseInternal(std::shared_ptr<RequestInternal> aRequest):
        m_request(aRequest)
        {
        m_body_writer = aRequest->m_body_writer;
        if (m_body_writer == nullptr)
            m_body_writer = [this](const void* aSource,size_t aBytes)->size_t { return StandardWriteFunc(aSource,aBytes); };

        if (!aRequest->m_platform_open)
            {
            m_code = ConnectionError;
            m_complete = true;
            return;
            }

        LPCWSTR extra_headers = WINHTTP_NO_ADDITIONAL_HEADERS;
        std::wstring content_length_header;
        size_t content_length = m_request->m_body_reader(nullptr,0);
        if (content_length > 0)
            {
            content_length_header = L"Content-Length: " + std::to_wstring(content_length);
            extra_headers = content_length_header.c_str();
            }
        if (!WinHttpSendRequest(m_request->m_request,extra_headers,DWORD(-1),nullptr,0,0,(DWORD_PTR)this))
            {
            m_code = ConnectionError;
            m_complete = true;
            }
        }

    ResponseInternal::~ResponseInternal()
        {
        }

#endif  // __WINDOWS__

#ifdef __ANDROID__

JavaVM* getVM()
    {
    if (globalVM == NULL)
        {
        LOGE("Panic: No VM configured, exiting.");
        exit(42);
        }
    return globalVM;
    }

JNIEnv* getEnv()
    {
    JavaVM* vm = getVM();
    JNIEnv* env = nullptr;
    vm->AttachCurrentThread(&env,nullptr);
    return env;
    }

bool Catch(JNIEnv* env)
    {
    bool thrown = env->ExceptionCheck();
    if (thrown)
        env->ExceptionDescribe();
    return thrown;
    }

jmethodID getMethod(JNIEnv* env, jobject instance, const char* method, const char* sig)
    {
    jclass clazz = env->GetObjectClass(instance);
    return env->GetMethodID(clazz,method,sig);
    }

jobject call(JNIEnv* env, jobject instance, const char* method, const char* sig, ...)
    {
    jmethodID methodID = getMethod(env, instance, method, sig);
    va_list args;
    va_start(args, sig);
    jobject result = env->CallObjectMethodV(instance, methodID, args);
    va_end(args);
    return result;
    }

void voidCall(JNIEnv* env, jobject instance, const char* method, const char* sig, ...)
    {
    jmethodID methodID = getMethod(env, instance, method, sig);
    va_list args;
    va_start(args, sig);
    env->CallVoidMethodV(instance, methodID, args);
    va_end(args);
    }

jint intCall(JNIEnv* env, jobject instance, const char* method, const char* sig, ...)
    {
    jmethodID methodID = getMethod(env, instance, method, sig);
    va_list args;
    va_start(args, sig);
    jint result = env->CallIntMethodV(instance, methodID, args);
    va_end(args);
    return result;
    }

void PlatformInit(InitData aInitData)
    {
    globalVM = aInitData;
    }

void RequestInternal::PlatformOpen()
    {
    JNIEnv* env = getEnv();
    jclass URL = env->FindClass("java/net/URL");
    jmethodID newURL = env->GetMethodID(URL, "<init>", "(Ljava/lang/String;)V");
    jstring urlString = env->NewStringUTF(m_url.c_str());
    jobject url = env->NewObject(URL, newURL, urlString);
    if (!Catch(env))
        {
        m_url_object = env->NewGlobalRef(url);
        m_platform_open = true;
        }
    }

void RequestInternal::PlatformClose()
    {
    JNIEnv* env = getEnv();
    env->DeleteGlobalRef(m_url_object);
    }

void* ProcessRequestFunction(void* aResponse)
    {
    ((ResponseInternal*)aResponse)->ProcessRequest();
    return nullptr;
    }

ResponseInternal::ResponseInternal(std::shared_ptr<RequestInternal> aRequest):
    m_request(aRequest)
    {
    m_body_writer = aRequest->m_body_writer;
    if (m_body_writer == nullptr)
        m_body_writer = [this](const void *aSource, size_t aBytes) -> size_t
            { return StandardWriteFunc(aSource, aBytes); };

    if (!aRequest->m_platform_open)
        {
        m_code = ConnectionError;
        m_complete = true;
        return;
        }

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    pthread_create(&m_worker_thread, &attr, ProcessRequestFunction, this);
    pthread_setname_np(m_worker_thread, "naext worker thread");
    }

void ResponseInternal::ProcessRequest()
    {
    JNIEnv* env = getEnv();
    env->PushLocalFrame(10);

    auto finally = [&]()
        {
        m_complete = true;
        env->DeleteLocalRef(buffer);
        env->PopLocalFrame(nullptr);
        JavaVM* vm = getVM();
        env->ExceptionClear();
        vm->DetachCurrentThread();
        m_worker_thread = 0;
        };

    jobject connection = call(env, m_request->m_url_object, "openConnection", "()Ljava/net/URLConnection;");
    if (Catch (env))
        {
        m_code = ConnectionError;
        finally();
        return;
        }

    for (const auto& header : m_request->m_headers)
        {
        jstring name = env->NewStringUTF(header.first.c_str());
        jstring value = env->NewStringUTF(header.second.c_str());
        voidCall(env, connection, "addRequestProperty", "(Ljava/lang/String;Ljava/lang/String;)V", name, value);
        env->DeleteLocalRef(name);
        env->DeleteLocalRef(value);
        }

    jobject outputStream = nullptr;
    if (m_request->m_method == "POST" || m_request->m_method == "PUT" || m_request->m_method == "PATCH" || m_request->m_method == "DELETE")
        {
        voidCall(env, connection, "setDoOutput", "(Z)V", 1);
        outputStream = call(env, connection, "getOutputStream", "()Ljava/io/OutputStream;");
        }
    jobject methodString = env->NewStringUTF(m_request->m_method.c_str());
    voidCall(env, connection, "setRequestMethod", "(Ljava/lang/String;)V", methodString);
    voidCall(env, connection, "setConnectTimeout", "(I)V", m_request->m_timeout_in_milliseconds);
    voidCall(env, connection, "setInstanceFollowRedirects", "(Z)V", 1);
    voidCall(env, connection, "connect", "()V");
    if (Catch (env))
        {
        m_code = ConnectionError;
        finally();
        return;
        }

    const int bufSize = 10240;
    jbyteArray buffer = env->NewByteArray(bufSize);
    char byteBuffer[bufSize];

    if (outputStream != nullptr)
        {
        int bytesRead = 0;
        if (m_request->m_body_reader)
            do
                {
                bytesRead = m_request->m_body_reader(byteBuffer,bufSize);
                if (bytesRead > 0)
                    {
                    env->SetByteArrayRegion(buffer, 0, bytesRead, (const jbyte*) byteBuffer);
                    voidCall(env, outputStream, "write", "([BII)V", buffer, 0, bytesRead);
                    }
                else
                    break;
                } while (!m_close_requested);
        voidCall(env, outputStream, "close", "()V");
        }

    jobject headerMap = call(env, connection, "getHeaderFields", "()Ljava/util/Map;");
    if (Catch (env))
        {
        m_code = ProtocolError;
        finally();
        return;
        }

    jobject headerSet = call(env, headerMap, "keySet", "()Ljava/util/Set;");
    jobjectArray headers = (jobjectArray)call(env, headerSet, "toArray", "()[Ljava/lang/Object;");
    jsize headerCount = env->GetArrayLength(headers);

    for (int i = 0; i < headerCount; i++)
        {
        jstring name = (jstring)env->GetObjectArrayElement(headers, i);
        if (!name)
            continue;
        const char* nameString = env->GetStringUTFChars(name, nullptr);

        jobject values = call(env, headerMap, "get", "(Ljava/lang/Object;)Ljava/lang/Object;", name);
        jstring value = (jstring)call(env, values, "get", "(I)Ljava/lang/Object;", 0);
        const char* valueString = env->GetStringUTFChars(value, nullptr);

        m_headers[nameString] = valueString;

        env->ReleaseStringUTFChars(name, nameString);
        env->ReleaseStringUTFChars(value, valueString);

        env->DeleteLocalRef(name);
        env->DeleteLocalRef(value);
        env->DeleteLocalRef(values);
        }

    int statusCode = intCall(env, connection, "getResponseCode", "()I");

    jobject inputStream = nullptr;

    if (statusCode >= 400)
        inputStream = call(env, connection, "getErrorStream", "()Ljava/io/InputStream;");
    else
        inputStream = call(env, connection, "getInputStream", "()Ljava/io/InputStream;");

    if (Catch(env))
        {
        m_code = ProtocolError;
        finally();
        return;
        }

    jint bytesRead = 0;
    do {
        bytesRead = intCall(env, inputStream, "read", "([B)I", buffer);
        if (Catch (env))
            {
            m_code = ReadError;
            finally();
            return;
            }
        if (bytesRead < 0)
            break;
        env->GetByteArrayRegion(buffer, 0, bytesRead, (jbyte*) byteBuffer);
        m_body_writer(byteBuffer,bytesRead);
        } while (!m_close_requested);

    voidCall(env, inputStream, "close", "()V");
    m_code = statusCode;
    finally();
    }

ResponseInternal::~ResponseInternal()
    {
    m_close_requested = true;
    if (m_worker_thread != 0)
        {
        int joinResult = pthread_join(m_worker_thread, nullptr);
        if (joinResult != 0)
            LOGE("Failed to join: %s", strerror(joinResult));
        }
    }

#endif  // __ANDROID__

}
