<?php
// Configurações do banco de dados
$servername = "localhost";
$username = "tdssl231t_luismachado";
$password = "Ay65Z3rTJXZO9SK";
$dbname = "tdssl231t_luismachado";

// Cria conexão com o banco de dados
$conn = new mysqli($servername, $username, $password, $dbname);

// Verifica a conexão
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error); // Se houver erro na conexão, interrompe o script e exibe a mensagem de erro.
}

// Define o cabeçalho para JSON
header('Content-Type: application/json'); // Configura o cabeçalho para que a resposta seja enviada no formato JSON.

// Lê os dados da solicitação recebida como JSON e converte para array associativo
$input = json_decode(file_get_contents('php://input'), true); // Lê o corpo da requisição HTTP, decodifica o JSON e o armazena em um array.

// Função para limpar dados
function clean_input($data) {
    global $conn;
    return mysqli_real_escape_string($conn, htmlspecialchars($data)); // Escapa caracteres especiais e previne ataques XSS.
}

// Verifica se há uma ação especificada na URL (ex: ?action=register)
if (isset($_GET['action'])) { // Verifica se o parâmetro 'action' está presente na URL.
    $action = $_GET['action']; // Obtém o valor da ação.

    // Se a ação for 'register', realiza o registro de um novo usuário
    if ($action == 'register') {
        $username = clean_input($input['username']); // Limpa e armazena o nome de usuário recebido.
        $password = password_hash(clean_input($input['password']), PASSWORD_DEFAULT); // Limpa e aplica um hash à senha.
        $email = clean_input($input['email']); // Limpa e armazena o email.

        // Verifica se o nome de usuário já existe no banco de dados
        $stmt = $conn->prepare("SELECT * FROM users WHERE username=?"); // Prepara a consulta SQL.
        $stmt->bind_param("s", $username); // Associa o valor do nome de usuário ao parâmetro.
        $stmt->execute(); // Executa a consulta.
        $result = $stmt->get_result(); // Armazena o resultado da consulta.

        // Se o nome de usuário já existir, retorna uma mensagem de erro
        if ($result->num_rows > 0) {
            echo json_encode(['success' => false, 'message' => 'Username already exists']); // Informa que o nome de usuário já existe.
        } else {
            // Insere o novo usuário no banco de dados
            $stmt = $conn->prepare("INSERT INTO users (username, password, email) VALUES (?, ?, ?)");
            $stmt->bind_param("sss", $username, $password, $email); // Associa os valores aos parâmetros.
            if ($stmt->execute()) {
                echo json_encode(['success' => true, 'message' => 'Registration successful']); // Informa que o registro foi bem-sucedido.
            } else {
                echo json_encode(['success' => false, 'message' => 'Error: ' . $stmt->error]); // Exibe erro caso ocorra.
            }
        }
        $stmt->close(); // Fecha a declaração preparada.
    
    // Se a ação for 'login', realiza o login do usuário
    } elseif ($action == 'login') {
        $username = clean_input($input['username']); // Limpa e armazena o nome de usuário.
        $password = clean_input($input['password']); // Limpa e armazena a senha.

        // Verifica se o usuário existe no banco de dados
        $stmt = $conn->prepare("SELECT * FROM users WHERE username=?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();

        // Se o usuário for encontrado, verifica a senha
        if ($result->num_rows > 0) {
            $user = $result->fetch_assoc(); // Obtém os dados do usuário.
            if (password_verify($password, $user['password'])) { // Verifica se a senha fornecida é correta.
                echo json_encode(['success' => true, 'message' => 'Login successful', 'email' => $user['email']]);
            } else {
                echo json_encode(['success' => false, 'message' => 'Incorrect password']); // Informa que a senha está incorreta.
            }
        } else {
            echo json_encode(['success' => false, 'message' => 'Username not found']); // Informa que o nome de usuário não foi encontrado.
        }
        $stmt->close();

    // Se a ação for 'update', atualiza as informações do usuário
    } elseif ($action == 'update') {
        $username = clean_input($input['username']); // Limpa e armazena o nome de usuário.
        $password = password_hash(clean_input($input['password']), PASSWORD_DEFAULT); // Limpa e aplica um hash à nova senha.
        $email = clean_input($input['email']); // Limpa e armazena o novo email.

        // Atualiza a senha e o email do usuário no banco de dados
        $stmt = $conn->prepare("UPDATE users SET password=?, email=? WHERE username=?");
        $stmt->bind_param("sss", $password, $email, $username);
        if ($stmt->execute()) {
            echo json_encode(['success' => true, 'message' => 'Update successful']); // Informa que a atualização foi bem-sucedida.
        } else {
            echo json_encode(['success' => false, 'message' => 'Error: ' . $stmt->error]); // Exibe erro caso ocorra.
        }
        $stmt->close();

    // Se a ação for 'delete', exclui o usuário do banco de dados
    } elseif ($action == 'delete') {
        $username = clean_input($input['username']); // Limpa e armazena o nome de usuário.

        // Exclui o usuário com o nome de usuário especificado
        $stmt = $conn->prepare("DELETE FROM users WHERE username=?");
        $stmt->bind_param("s", $username);
        if ($stmt->execute()) {
            echo json_encode(['success' => true, 'message' => 'User deleted successfully']); // Informa que o usuário foi excluído com sucesso.
        } else {
            echo json_encode(['success' => false, 'message' => 'Error: ' . $stmt->error]); // Exibe erro caso ocorra.
        }
        $stmt->close();
    }
}

$conn->close(); // Fecha a conexão com o banco de dados.
?>
