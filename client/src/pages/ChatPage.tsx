import { Lock } from 'lucide-react';
import { ChatView } from '../components/ChatView';
import { Sidebar } from '../components/Sidebar';
import { useStore } from '../store';

export function ChatPage() {
  const activeId = useStore((s) => s.activeId);
  const exists = useStore((s) => s.conversations.some((c) => c.id === s.activeId));

  return (
    <div className="flex h-full overflow-hidden">
      {/* On phones only one pane shows at a time. */}
      <div className={`${activeId ? 'hidden md:flex' : 'flex'} w-full shrink-0 md:w-80 lg:w-96`}>
        <Sidebar />
      </div>
      <main className={`${activeId ? 'flex' : 'hidden md:flex'} min-w-0 flex-1 flex-col border-l border-ink-800`}>
        {activeId && exists ? (
          <ChatView key={activeId} conversationId={activeId} />
        ) : (
          <div className="flex flex-1 flex-col items-center justify-center gap-4 px-6 text-center">
            <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-accent/10 text-accent">
              <Lock className="h-7 w-7" />
            </div>
            <div>
              <p className="font-medium">Pick a conversation</p>
              <p className="mt-1 max-w-xs text-sm text-ink-400">
                Messages are encrypted in your browser before they are sent. The server stores ciphertext only.
              </p>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
