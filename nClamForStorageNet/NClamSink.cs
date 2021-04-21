namespace Storage.Net.Blobs.Sinks
{
    using nClam; 

    using System;
    using System.IO;
    using System.Threading.Tasks;

    public class NClamSink : ITransformSink
    {
        private static T Forget<T>(Task<T> task)
        {
            return task.ConfigureAwait(false).GetAwaiter().GetResult();
        }

        private class EmptyStream : MemoryStream
        {
            internal EmptyStream() : base(Array.Empty<byte>())
            {
            }
        }

        protected Func<IClamClient> NClamClientFactory { get; }
        protected Action<ClamScanResult> VirusDetectedCallback { get; }

        public NClamSink(Func<IClamClient> clientFactory, Action<ClamScanResult> virusDetectedCallback)
        {
            this.NClamClientFactory = clientFactory;
            this.VirusDetectedCallback = virusDetectedCallback;
        }

        public virtual Stream OpenReadStream(string fullPath, Stream parentStream)
        {
            return ScanVirus(fullPath, parentStream);
        }

        protected virtual Stream ScanVirus(string fullPath, Stream parentStream)
        {
            var client = NClamClientFactory();
            if (Forget(client.TryPingAsync()))
            {
                var stream = default(Stream);
                if (!parentStream.CanSeek)
                {
                    stream = new MemoryStream();
                    parentStream.CopyTo(stream);
                }
                else
                {
                    stream = parentStream;
                }
                stream.Seek(0, SeekOrigin.Begin);

                var scanResult = Forget(client.SendAndScanFileAsync(stream));
                if (!scanResult.Result.Equals(ClamScanResults.Clean))
                {
                    VirusDetectedCallback?.Invoke(scanResult);
                    return new EmptyStream();
                }
                else
                {
                    stream.Seek(0, SeekOrigin.Begin);
                    return stream;
                }
            }

            return parentStream;
        }

        public virtual Stream OpenWriteStream(string fullPath, Stream parentStream)
        {
            return ScanVirus(fullPath, parentStream);
        }
    }

}
