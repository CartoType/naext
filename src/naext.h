/*
naext.h

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

#pragma once

#include <functional>
#include <memory>
#include <string>

#if __ANDROID__
#include <jni.h>
#endif

namespace Naext
{

#ifdef __ANDROID__
using InitData = JavaVM*;
#else
using InitData = void*;
#endif

class Request;
class RequestInternal;
class ResponseInternal;

/**
Global initialisation method.
Call this function to initialise the library.
*/
void Init(InitData aInitData);

/// If ReadFunc is called with a null dest it must respond with the body size.
using ReadFunc = std::function<size_t(void* aDest,size_t aBufferSize)>;
using WriteFunc = std::function<size_t(const void* aSource,size_t aBytes)>;
using HeaderLister = std::function<bool(const char* aName,const char* aValue)>;

enum Status
    {
    ConnectionError = -1,
    ProtocolError = -2,
    ReadError = -3,
    WriteError = -4,
    GenericError = -5,
    Processing = 0
    };

class Response
    {
    friend class Request;
    Response() = default;

    public:
    /// Checks if a response is complete, with a result or with an error.
    bool IsComplete();
    /**
    Returns the status of a response.
    Positive codes are HTTP status codes returned by the server.
    Negative codes are processing errors defined in Naext::Status.
    */
    int Status();
    /// Returns the body of the response unless a body reader has been provided.
    const std::string& Body();
    /// Returns a header for a given name.
    const char* Header(const char* aName);
    /// Lists the headers, stopping if the lister function returns false.
    void ListHeaders(HeaderLister aLister);
    /// Returns the request that initiated this reponse.
    Naext::Request Request();

    private:
    explicit Response(std::shared_ptr<ResponseInternal> aInternal);

    std::shared_ptr<ResponseInternal> m_internal;
    };

class Request
    {
    friend class Response;

    public:
    explicit Request(const char* aUrl);
    ~Request();

    Request(const Request&) = delete;
    void operator=(const Request&) = delete;
    void operator=(Request&&) = delete;

    /// Sets the request method. Defaults to "GET".
    void SetMethod(const char* aMethod);
    /// Adds a request header.
    void AddHeader(const char* aName,const char* aValue);
    /// Sets the request body from a block of data.
    void SetBody(const char* aBody,int aSize);
    /// Sets the request body using a reader.
    void SetBody(ReadFunc aReader);
    /// Sets the response body writer.
    void SetResponseBodyWriter(WriteFunc aWriter);
    /// Sets the connection timeout in milliseconds.
    void SetTimeout(int aMilliseconds);

    /**
    Sends a request and returns a response object.
    The actual request is processed asynchronously.
    Use IsComplete to check whether the response is complete.

    A request object can be reused multiple times to make requests, but
    there can be only one active request using the same request object.
    */
    Response Send();

    private:
    explicit Request(std::shared_ptr<RequestInternal> aInternal);
    Request(Request&&) = default;

    std::shared_ptr<RequestInternal> m_internal;
    };

}
