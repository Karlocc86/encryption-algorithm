# KDSPN-64 · animación

Animación paso a paso del cifrado de bloques de juguete KDSPN-64 (SPN con tablas
derivadas de la clave): de la clave a las tablas, del texto a los bloques CBC, las
10 rondas y la salida, al cifrar y al descifrar.

**Es un proyecto didáctico.** KDSPN-64 no es seguro: no lo uses para proteger datos reales.

## Cómo correrlo

Requiere Node 20 o superior.

```
npm install
npm run dev      # servidor de desarrollo
npm test         # pruebas (vitest)
npm run build    # revisa tipos y genera dist/
```

El resto del README (estructura, ruta de la demo de 5 minutos) se completa en la Fase 7.
