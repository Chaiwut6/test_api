<?php

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

header('Access-Control-Allow-Origin: *');
header("Access-Control-Allow-Credentials: true");
header('Access-Control-Allow-Methods: GET, PUT, POST, DELETE, OPTIONS');
header('Access-Control-Max-Age: 1000');
header('Access-Control-Allow-Headers: Origin, Content-Type, X-Auth-Token , Authorization');
require_once './DbHandler.php';
require_once '../include/Config.php';
require '../../vendor/autoload.php';
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Server\RequestHandlerInterface as RequestHandler;
use Slim\Factory\AppFactory;
use Psr\Http\Message\ResponseInterface as Response;

$user_id = NULL;
$app = AppFactory::create();
$app->setBasePath('/test_api/api/v1');

$authMiddleware = function (Request $request, RequestHandler $handler) {
    $headers = $request->getHeaders();
    $response = new \Slim\Psr7\Response();
    // echo $headers['Authorization'][0];
    // exit;
    if (isset($headers['Authorization'][0])) {
        $db = new DbHandler();
        $api_key = $headers['Authorization'][0];

        if (!$db->isValidApiKey($api_key)) {
            $response = $response->withStatus(401);
            $response->getBody()->write(json_encode([
                "res_code" => "09",
                "res_text" => "Api key ไม่ถูกต้อง ไม่มีสิทธิ์การเข้าถึงข้อมูล"
            ]));
            return $response->withHeader('Content-Type', 'application/json');
        } else {
            // You can set user ID in the request attributes if needed
            $user_id = $db->getUserId($api_key);
            $request = $request->withAttribute('user_id', $user_id);
        }
    } else {
        $response = $response->withStatus(401);
        $response->getBody()->write(json_encode([
            "res_code" => "09",
            "res_text" => "ไม่พบ Api key"
        ]));
        return $response->withHeader('Content-Type', 'application/json');
    }

    return $handler->handle($request);
};

$app->post('/checkapi', function($request, $response, $args) use ($app) {
    $data = array();
    $data["res_code"] = "00";
    $data["res_text"] = "แสดงข้อมูลสำเร็จ";
    return echoRespnse($response, 200, $data);
});

$app->post('/register', function($request, $response, $args) use ($app) {
    $fname = $request->getParsedBody()['fname']; 
    $lname = $request->getParsedBody()['lname']; 
    $email = $request->getParsedBody()['email'];
    $password = $request->getParsedBody()['password'];
    $status = 0; 

    $db = new DbHandler();
    $result = $db->register($fname, $lname, $email, $password, $status);

    if ($result['res_code'] === '00') {
        $data["res_code"] = "00";
        $data["res_text"] = "ลงทะเบียนสำเร็จ";
    } else {
        $data["res_code"] = "01";
        $data["res_text"] = "ลงทะเบียนไม่สำเร็จ: " . $result['res_text']; 
    }
    
    return echoRespnse($response, 200, $data);
});


$app->post('/login', function($request, $response, $args) use ($app) {
    $parsedBody = $request->getParsedBody();


    $email = $parsedBody['email']; 
    $password = $parsedBody['password'];
    $status = 1; 
   
    $db = new DbHandler();
    $result = $db->login($email, $password, $status);
    
    $data = array();
    if ($result['res_code'] === '00') {
        $data["res_code"] = "00";
        $data["res_text"] = "ล็อกอินสำเร็จ";
        $data["res_result"] = $result;
    } else {
        $data["res_code"] = "01";
        $data["res_text"] = "ล็อกอินไม่สำเร็จ";
        $data["res_result"] = $result;
    }
    return echoRespnse($response, 200, $data);
});


 
$app->post('/update', function($request, $response, $args) use ($app) {
    // $id = $request->getParsedBody()['id'];
    $user_id = $request->getAttribute('user_id');
    $fname = $request->getParsedBody()['fname'];
    $lname = $request->getParsedBody()['lname'];
    $email = $request->getParsedBody()['email'];

    $db = new DbHandler();
    $result = $db->updateUser($user_id, $fname, $lname, $email);
    
    if ($result) {
        $data = array("res_code" => "00", "res_text" => "อัปเดตข้อมูลสำเร็จ");
    } else {
        $data = array("res_code" => "01", "res_text" => "อัปเดตข้อมูลไม่สำเร็จ");
    }
    
    return echoRespnse($response, 200, $data);
})->add($authMiddleware);

$app->post('/delete', function($request, $response, $args) use ($app) {
    // $data = $request->getParsedBody();
    // $id = $data['id'];
    $user_id = $request->getAttribute('user_id');
    $db = new DbHandler();
    $result = $db->delete($user_id);

    return echoRespnse($response, 200, $result);
})->add($authMiddleware);

$app->post('/change_password', function($request, $response, $args) use ($app) {

    // $id = $request->getParsedBody()['id'];
    $user_id = $request->getAttribute('user_id');
    $oldPassword = $request->getParsedBody()['oldPassword'];
    $newPassword = $request->getParsedBody()['newPassword'];
    
    $db = new DbHandler();
    $result = $db->changePassword($user_id, $oldPassword, $newPassword);
    
    return echoRespnse($response, 200, $result);
 })->add($authMiddleware);



 $app->post('/images', function($request, $response, $args) use ($app) {
    $user_id = $request->getAttribute('user_id');
    
    if (isset($_FILES['image'])) {
        error_log("มีความพยายามอัพโหลดไฟล์.");

        if ($_FILES['image']['error'] == UPLOAD_ERR_OK) {
            $uploadDir = 'image/'; // path ย่อ
            // $uploadDir = __DIR__ . '/image/'; // path เต็ม
            
            $fileExtension = pathinfo($_FILES['image']['name'], PATHINFO_EXTENSION);
            $newFileName = date('YmdHis') . '.' . $fileExtension;
            $uploadFile = $uploadDir . $newFileName;
            
            if (move_uploaded_file($_FILES['image']['tmp_name'], $uploadFile)) {
                $db = new DbHandler();
                $result = $db->images($user_id, $uploadFile);

                if ($result) {
                    return echoRespnse($response, 200, ["message" => "อัพโหลดรูปสำเร็จ", "result" => $result]);
                } else {
                    return echoRespnse($response, 404, ["error" => "อัพเดตไม่สำเร็จ"]);
                }
            }
        }
    } else {
        return echoRespnse($response, 400, ["error" => "ไม่มีรูปภาพอัพโหลด"]);
    }
})->add($authMiddleware);

$app->get('/banner', function($request, $response, $args) use ($app) {

   $db = new DbHandler();
   $result = $db->banner();
   $data = array();
   if ($result != NULL) {
       $data["res_code"] = "00";
       $data["res_text"] = "ดึงข้อมูลสำเร็จ";
       $data["res_result"] = $result;
   } else {
       $data["res_code"] = "01";
       $data["res_text"] = "ดึงข้อมูลไม่สำเร็จ";
   }
   return echoRespnse($response, 200, $data);
});

$app->post('/MemberDetail', function($request, $response, $args) use ($app) {
    // $data = $request->getParsedBody();
    // error_log("Request Data: " . json_encode($data)); 
    // $id = $data['id'];
    $user_id = $request->getAttribute('user_id');
    $db = new DbHandler();
    $result = $db->getMemberDetail($user_id);

    return echoRespnse($response, 200, $result);
})->add($authMiddleware);


// ***************************************************************************************************
// ***************************************************************************************************
// ***************************************************************************************************

        /*** แสดงผล json ***/
        function echoRespnse($response, $status_code, $data) {
            $response = $response->withStatus($status_code)
                                ->withHeader('Content-Type', 'application/json');
            $response->getBody()->write(json_encode($data));
            return $response;
        }

        

        

// ***************************************************************************************************
// ***************************************************************************************************
// ***************************************************************************************************







$app->run();
?>
