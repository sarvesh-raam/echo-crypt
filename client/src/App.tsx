import { Loader2 } from 'lucide-react';
import { useEffect } from 'react';
import { AuthPage } from './pages/AuthPage';
import { LegalPage } from './pages/LegalPage';
import { ChatPage } from './pages/ChatPage';
import { useStore } from './store';

const LEGAL = { '/privacy': 'privacy', '/terms': 'terms' } as const;

export function App() {
  const legal = LEGAL[window.location.pathname as keyof typeof LEGAL];
  return legal ? <LegalPage page={legal} /> : <Chat />;
}

function Chat() {
  const phase = useStore((s) => s.phase);
  const boot = useStore((s) => s.boot);
  const unread = useStore((s) => Object.values(s.unread).reduce((a, b) => a + b, 0));

  useEffect(() => {
    void boot();
  }, [boot]);

  useEffect(() => {
    document.title = unread > 0 ? `(${unread}) EchoCrypt` : 'EchoCrypt';
  }, [unread]);

  // Messages that arrived while the tab was hidden count as unread until you come back.
  useEffect(() => {
    const onVisible = () => {
      const { activeId, unread: counts } = useStore.getState();
      if (!document.hidden && activeId && counts[activeId]) useStore.setState({ unread: { ...counts, [activeId]: 0 } });
    };
    document.addEventListener('visibilitychange', onVisible);
    return () => document.removeEventListener('visibilitychange', onVisible);
  }, []);

  if (phase === 'booting') {
    return (
      <div className="flex h-full items-center justify-center text-ink-400">
        <Loader2 className="h-6 w-6 animate-spin" />
      </div>
    );
  }
  return phase === 'ready' ? <ChatPage /> : <AuthPage />;
}
