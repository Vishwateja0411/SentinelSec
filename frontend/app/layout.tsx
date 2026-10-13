import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'SentinelSec — Security Assessment Management Platform',
  description: 'Defensive security assessment management and target authorization registry.',
  icons: {
    icon: '/favicon.ico',
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="bg-navy-900 text-slate-100 antialiased selection:bg-cyber-blue selection:text-white">
        {children}
      </body>
    </html>
  );
}
