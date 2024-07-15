<?php
// Configurações do banco de dados
$servername = "localhost"; // Nome do servidor MySQL
$username = "tdssl231t_seu_nome"; // Nome de usuário do banco de dados
$password = "suasenha"; // Senha do banco de dados
$dbname = "seubanco"; // Nome do banco de dados

// Cria conexão com o banco de dados
$conn = new mysqli($servername, $username, $password, $dbname);

// Verifica a conexão
if ($conn->connect_error) {
    // Se houver erro na conexão, exibe mensagem de erro e interrompe o script
    die("Connection failed: " . $conn->connect_error);
}

// Define o cabeçalho para JSON
header('Content-Type: application/json');

// Lê os dados da solicitação recebida como JSON e converte para array associativo
$input = json_decode(file_get_contents('php://input'), true);

// Verifica se há uma ação especificada na URL (ex: ?action=register)
if (isset($_GET['action'])) {
    $action = $_GET['action']; // Obtém o valor da ação

    // Ação para registrar um novo usuário
    if ($action == 'register') {
        $username = $input['username']; // Obtém o nome de usuário do input JSON
        $password = password_hash($input['password'], PASSWORD_DEFAULT); // Cria um hash da senha fornecida
        $email = $input['email']; // Obtém o email do input JSON

        // Verifica se o nome de usuário já existe no banco de dados
        $stmt = $conn->prepare("SELECT * FROM users WHERE username=?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();

        // Se o nome de usuário já estiver em uso, retorna mensagem de erro
        if ($result->num_rows > 0) {
            echo json_encode(['success' => false, 'message' => 'Username already exists']);
        } else {
            // Insere um novo usuário no banco de dados
            $stmt = $conn->prepare("INSERT INTO users (username, password, email) VALUES (?, ?, ?)");
            $stmt->bind_param("sss", $username, $password, $email);
            
            // Verifica se a inserção foi bem-sucedida e retorna mensagem correspondente
            if ($stmt->execute()) {
                echo json_encode(['success' => true, 'message' => 'Registration successful']);
            } else {
                echo json_encode(['success' => false, 'message' => 'Error: ' . $stmt->error]);
            }
        }
        $stmt->close(); // Fecha a declaração preparada
    } 
    // Ação para realizar login de usuário
    elseif ($action == 'login') {
        $username = $input['username']; // Obtém o nome de usuário do input JSON
        $password = $input['password']; // Obtém a senha do input JSON

        // Verifica se o nome de usuário e a senha estão corretos
        $stmt = $conn->prepare("SELECT * FROM users WHERE username=?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();

        // Se encontrar o usuário no banco de dados
        if ($result->num_rows > 0) {
            $user = $result->fetch_assoc(); // Obtém os dados do usuário como um array associativo
            // Verifica se a senha fornecida corresponde à senha armazenada (usando função password_verify)
            if (password_verify($password, $user['password'])) {
                echo json_encode(['success' => true, 'message' => 'Login successful', 'email' => $user['email']]);
            } else {
                echo json_encode(['success' => false, 'message' => 'Incorrect password']);
            }
        } else {
            echo json_encode(['success' => false, 'message' => 'Username not found']);
        }
        $stmt->close(); // Fecha a declaração preparada
    } 
    // Ação para atualizar dados do usuário
    elseif ($action == 'update') {
        $username = $input['username']; // Obtém o nome de usuário do input JSON
        $password = password_hash($input['password'], PASSWORD_DEFAULT); // Cria um novo hash da senha
        $email = $input['email']; // Obtém o email do input JSON

        // Atualiza os dados do usuário no banco de dados
        $stmt = $conn->prepare("UPDATE users SET password=?, email=? WHERE username=?");
        $stmt->bind_param("sss", $password, $email, $username);
        
        // Verifica se a atualização foi bem-sucedida e retorna mensagem correspondente
        if ($stmt->execute()) {
            echo json_encode(['success' => true, 'message' => 'Update successful']);
        } else {
            echo json_encode(['success' => false, 'message' => 'Error: ' . $stmt->error]);
        }
        $stmt->close(); // Fecha a declaração preparada
    } 
    // Ação para deletar um usuário
    elseif ($action == 'delete') {
        $username = $input['username']; // Obtém o nome de usuário do input JSON

        // Deleta o usuário do banco de dados
        $stmt = $conn->prepare("DELETE FROM users WHERE username=?");
        $stmt->bind_param("s", $username);
        
        // Verifica se a exclusão foi bem-sucedida e retorna mensagem correspondente
        if ($stmt->execute()) {
            echo json_encode(['success' => true, 'message' => 'User deleted successfully']);
        } else {
            echo json_encode(['success' => false, 'message' => 'Error: ' . $stmt->error]);
        }
        $stmt->close(); // Fecha a declaração preparada
    }
}

$conn->close(); // Fecha a conexão com o banco de dados
?>




