import { Sun, Moon } from 'lucide-react';
import { useTheme } from '../context/ThemeContext';

export default function ThemeToggle() {
  const { theme, toggleTheme } = useTheme();

  return (
    <button
      onClick={toggleTheme}
      className="p-2 rounded-md hover:bg-brand-surface text-brand-muted hover:text-brand-text transition-all duration-200"
      title={theme === 'light' ? 'Switch to Dark Mode' : 'Switch to Light Mode'}
    >
      {theme === 'light' ? (
        <Moon size={18} className="animate-in fade-in zoom-in duration-300" />
      ) : (
        <Sun size={18} className="animate-in fade-in zoom-in duration-300 text-brand-cyan" />
      )}
    </button>
  );
}
