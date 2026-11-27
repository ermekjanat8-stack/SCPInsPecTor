import {defineConfig} from 'vite';
import react from '@vitejs/plugin-react';
export default defineConfig({plugins:[react()],base:'./',server:{proxy:{'/api':'http://127.0.0.1:8787','/demo':'http://127.0.0.1:8787','/demo.js':'http://127.0.0.1:8787','/sample.svg':'http://127.0.0.1:8787'}}});
