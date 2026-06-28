import { useState } from 'react';
import MainDisplay from './views/MainDisplay';
import SestinaBootScreen from './components/SestinaBootScreen';

/**
 * App — Main application shell for Sestina.
 * Single-page application, no routing required.
 */
export default function App() {
  const [isBooted, setIsBooted] = useState(false);

  return (
    <>
      {!isBooted && (
        <SestinaBootScreen onBootComplete={() => setIsBooted(true)} />
      )}
      <MainDisplay />
    </>
  );
}

