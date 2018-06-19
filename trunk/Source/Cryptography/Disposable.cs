using System;

namespace Infotecs.Cryptography
{
    public abstract class Disposable : IDisposable
    {
        protected bool Disposed = false;

        public void Dispose()
        {
            if (Disposed) return;
            lock (this)
            {
                if (Disposed) return;
                DoDispose();
                Disposed = true;
            }
        }

        protected abstract void DoDispose();
    }
}