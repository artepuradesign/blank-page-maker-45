<?php
// src/endpoints/user-premium-status.php

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../config/cors.php';
require_once __DIR__ . '/../middleware/auth.php';
require_once __DIR__ . '/../utils/Response.php';

try {
    setCORSHeaders();
    
    if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
        http_response_code(200);
        exit();
    }
    
    $db = getDBConnection();
    
    $authUser = authenticate($db);
    if (!$authUser) {
        Response::error('Token inválido ou expirado', 401);
        exit();
    }
    
    $userId = $authUser['id'];
    $method = $_SERVER['REQUEST_METHOD'];
    
    // GET - Retornar status premium do usuário
    if ($method === 'GET') {
        $stmt = $db->prepare("SELECT premium_enabled FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        
        Response::success([
            'premium_enabled' => (bool)($result['premium_enabled'] ?? false)
        ], 'Status premium recuperado com sucesso');
        
    // POST - Atualizar status premium do usuário
    } elseif ($method === 'POST') {
        $input = json_decode(file_get_contents('php://input'), true);
        
        if (!isset($input['premium_enabled'])) {
            Response::error('Campo premium_enabled é obrigatório', 400);
            exit();
        }
        
        $premiumEnabled = (bool)$input['premium_enabled'];
        
        $stmt = $db->prepare("UPDATE users SET premium_enabled = ? WHERE id = ?");
        $stmt->execute([$premiumEnabled ? 1 : 0, $userId]);
        
        Response::success([
            'premium_enabled' => $premiumEnabled
        ], $premiumEnabled ? 'Painéis Premium desbloqueados!' : 'Painéis Premium bloqueados');
        
    } else {
        Response::error('Método não permitido', 405);
    }
    
} catch (Exception $e) {
    error_log("USER_PREMIUM_STATUS ERROR: " . $e->getMessage());
    Response::error('Erro interno do servidor', 500);
}
