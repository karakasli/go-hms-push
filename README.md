你好！
很冒昧用这样的方式来和你沟通，如有打扰请忽略我的提交哈。我是光年实验室（gnlab.com）的HR，在招Golang开发工程师，我们是一个技术型团队，技术氛围非常好。全职和兼职都可以，不过最好是全职，工作地点杭州。
我们公司是做流量增长的，Golang负责开发SAAS平台的应用，我们做的很多应用是全新的，工作非常有挑战也很有意思，是国内很多大厂的顾问。
如果有兴趣的话加我微信：13515810775  ，也可以访问 https://gnlab.com/，联系客服转发给HR。
This project was forked from [github.com/HMS-Core/hms-push-serverdemo-go](https://github.com/HMS-Core/hms-push-serverdemo-go).

# Table of Contents
* [Introduction](#introduction)
* [Installation](#installation)
* [Configuration](#configuration)
* [Supported Environments](#supported-enviroment)
* [License](#license)


# Introduction
Golang sample code encapsulates APIs of the HUAWEI Push Kit server. It provides many sample programs for your reference or usage.

The following describes packages of Golang sample code.
| Package   | Description |
| ----------- | ----------- |  
|examples|Sample code packages. Each package can run independently.|
|httpclient|Common package for sending network requests.|
|push|Package where APIs of the HUAWEI Push Kit server are encapsulated.|

# Installation
Before using Golang sample code, check whether the Golang environment has been installed. Golang 1.11 or a later version is recommended.
Decompress the Golang sample code package.
    
Copy the org.huawei.com package in the decompressed folder to the project vendor directory in the path specified by GOPATH.
Refresh the project and ensure that the file is successfully copied to the destination directory.
    
# Configuration 
Golang sample code uses the Client structure in the push package as the entry. Each method in the Client structure calls an API of the HUAWEI Push Kit server.
The following describes methods in the Client structure.
| Method   | Description |
| ----------- | ----------- |    
|SendMessage|   Sends a message to a device.|

To use functions provided by packages in examples, you need to set related parameters in pushcommon.go in the common package.

The following describes parameters in pushcommon.go.
| Parameter   | Description |
| ----------- | ----------- |    
|appId|App ID, which is obtained from app information.|
|appSecret|Secret access key of an app, which is obtained from app information.|
|authUrl|URL for the Huawei OAuth 2.0 service to obtain a token, please refer to [Generating an App-Level Access Token](https://developer.huawei.com/consumer/en/doc/development/parts-Guides/generating_app_level_access_token).|
|pushUrl|URL for accessing HUAWEI Push Kit, please refer to [Sending Messages](https://developer.huawei.com/consumer/en/doc/development/HMS-References/push-sendapi).|

The following table describes parameters in target.go. 
| Parameter   | Description |
| ----------- | ----------- | 
|TargetTopic|Name of a topic to be subscribed to, unsubscribed from, or queried.|
|TargetCondition|Combination of condition expressions for a message.|
|TargetToken|Token of a target device, which is obtained from the device.|
|TargetTokenArray|Tokens of all target devices, which are obtained from the devices.|

# License
pushkit Go sample is licensed under the [Apache License, version 2.0](http://www.apache.org/licenses/LICENSE-2.0).

