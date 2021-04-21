## nClam for Storage.Net

see [Storage.Net](https://github.com/aloneguid/storage) and [nclam](https://github.com/tekmaven/nClam)  
this repo is just combine both libs with ```ITransformSink``` interface.

### Example

```csharp
using Storage.Net.Blobs;
using System.Net;

IBlobStorage blobStorage = StorageFactory
        .Blobs
        ./* blob storage service*/
        .WithNClam(
            endpoint: new IPEndPoint(IPAddress.Parse(ipString: "10.4.4.46"),port: 3310),
            virusDetectedCallback: r => Console.WriteLine(r.RawResult))
        .Build();
```

### License
Apache 2.0