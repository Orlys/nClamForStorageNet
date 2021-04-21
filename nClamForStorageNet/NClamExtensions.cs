namespace Storage.Net.Blobs
{
    using nClam;

    using Storage.Net.Blobs.Sinks;

    using System;
    using System.Net;

    public static class NClamExtensions
    {
        public static IBlobStorage WithNClam(this IBlobStorage blobStorage, IPEndPoint endpoint, Action<ClamScanResult> virusDetectedCallback = null)
            => WithNClam(blobStorage, () => new ClamClient(endpoint.Address, endpoint.Port), virusDetectedCallback);

        public static IBlobStorage WithNClam(this IBlobStorage blobStorage, Func<IClamClient> clientFactory, Action<ClamScanResult> virusDetectedCallback = null)
            => blobStorage.WithSinks(new NClamSink(clientFactory, virusDetectedCallback)); 
    }

}
