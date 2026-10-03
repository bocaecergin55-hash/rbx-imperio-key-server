# RBX Imperio — Key Server

Servidor simples de autenticação e painel de gerenciamento de keys para software próprio/autorizado.

## 1. Instalar
Requer Node.js 20+.

```bash
npm install
```

## 2. Configurar
Copie `.env.example` para `.env` e defina uma senha de administrador e um JWT_SECRET longo.

## 3. Rodar
```bash
npm start
```

Abra:
http://localhost:3000

## API do launcher

### Validar
POST `/api/validate`

```json
{
  "key": "RBX-ABCDEF-123456-789ABC",
  "hwid": "identificador-do-dispositivo"
}
```

Resposta válida:
```json
{
  "valid": true,
  "key": "RBX-...",
  "expires_at": "...",
  "hwid_bound": true
}
```

A primeira validação vincula a key ao HWID enviado. Depois disso, a mesma key só valida naquele dispositivo.

Antes de publicar na internet, coloque HTTPS e altere todas as credenciais/segredos padrão.
