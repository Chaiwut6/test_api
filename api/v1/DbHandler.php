<?php
use \Firebase\JWT\JWT;

class DbHandler { 
 
    private $conn,$func;
    function __construct() {
        require_once '../include/DbConnect.php';
        $db = new DbConnect();
        $this->conn = $db->connect();
    } 

   

public function register($fname, $lname, $email, $password) {
    
    $passwordHash = password_hash($password, PASSWORD_BCRYPT);
    
    $stmt = $this->conn->prepare("INSERT INTO members (member_fname, member_lname, member_email, member_password) VALUES (?, ?, ?, ?)");
 
    $stmt->bind_param("ssss", $fname, $lname, $email, $passwordHash);

    if ($stmt->execute()) {
        $stmt->close();
        return ['res_code' => '00', 'res_text' => 'ลงทะเบียนสำเร็จ'];
    } else {
        $stmt->close();
        return ['res_code' => '01', 'res_text' => 'เกิดข้อผิดพลาด: ' . $stmt->error];
    }
}

public function login($email, $password, $status) {
  $stmt = $this->conn->prepare("SELECT * FROM `members` WHERE member_email = ? AND (member_status = 0 OR member_status = 1)");
  $stmt->bind_param("s", $email);
  $stmt->execute();

  $result = $stmt->get_result();
  $output = array();

  if ($result->num_rows > 0) {
      $res = $result->fetch_assoc(); 

      if (password_verify($password, $res['member_password'])) { 
        
          $member_id = $res['member_id'];
          $member_email = $res['member_email'];

          $payload = array(
              "iat" => time(),
              "exp" => time() + (60 * 60), 
              "data" => array(
                  "id" => $member_id,
                  "email" => $member_email
              )
          );
          $secret_key = base64_encode(openssl_random_pseudo_bytes(32));
          $jwt = JWT::encode($payload, $secret_key, 'HS256');


          $updateStmt = $this->conn->prepare("UPDATE `members` SET member_status = ? WHERE member_id = ?");
          $updateStmt->bind_param("ii", $status, $member_id);
          $updateStmt->execute();
          $updateStmt->close();

          $response = array(
              "member_fname" => $res['member_fname'],
              "member_lname" => $res['member_lname'],
              "member_email" => $res['member_email'],
              "TOKEN" => $jwt
          );
          $stmt->close();
          $this->log($member_id, $jwt);

          $checkStmt = $this->conn->prepare("SELECT image_file FROM `images` WHERE member_id = ?");
          $checkStmt->bind_param("i", $member_id); 
          $checkStmt->execute();
          $checkResult = $checkStmt->get_result();
          
          if ($checkResult->num_rows > 0) {
              $row = $checkResult->fetch_assoc();
              $image_file = $row['image_file'];
              $this->images($member_id, $image_file);
          } else {
              $this->images($member_id, NULL);
          }
          
          $checkStmt->close();

          return ['res_code' => '00', 'res_result' => $response];
      } else {
          return ['res_code' => '01', 'res_text' => 'รหัสผ่านไม่ถูกต้อง'];
      }
  } else {
      return ['res_code' => '01', 'res_text' => 'ไม่พบข้อมูลผู้ใช้'];
  }
}

public function updateUser($member_id, $fname, $lname, $email) {
  $stmt = $this->conn->prepare("UPDATE `members` SET member_fname = ?, member_lname = ?, member_email = ? WHERE member_id = ?");
  $stmt->bind_param("sssi", $fname, $lname, $email, $member_id);
  
  if ($stmt->execute()) {
      $stmt->close();
      return true; 
  } else {

      $stmt->close();
      return false; 
  }
}

public function changePassword($member_id, $oldPassword, $newPassword) {
  $stmt = $this->conn->prepare("SELECT member_password FROM `members` WHERE member_id = ?");
  $stmt->bind_param("i", $member_id);
  $stmt->execute();
  
  $result = $stmt->get_result();
  
  if ($result->num_rows > 0) {
      $res = $result->fetch_assoc();
      
      if (password_verify($oldPassword, $res['member_password'])) {
          
          $hashedNewPassword = password_hash($newPassword, PASSWORD_DEFAULT);
          
          $updateStmt = $this->conn->prepare("UPDATE `members` SET member_password = ? WHERE member_id = ?");
          $updateStmt->bind_param("si", $hashedNewPassword, $member_id);
          $updateStmt->execute();
          $updateStmt->close();
          
          return ['res_code' => '00', 'res_text' => 'เปลี่ยนรหัสผ่านสำเร็จ'];
      } else {
          return ['res_code' => '01', 'res_text' => 'รหัสผ่านเก่าไม่ถูกต้อง'];
      }
  }
}



public function delete($member_id) {
    try {
        $stmt = $this->conn->prepare("DELETE FROM `images` WHERE member_id = ?");
        $stmt->bind_param("i", $member_id);
        
        if (!$stmt->execute()) {
            throw new Exception('Failed to delete from images');
        }
        $stmt->close();
        $stmt = $this->conn->prepare("DELETE FROM `members` WHERE member_id = ?");
        $stmt->bind_param("i", $member_id);

        if (!$stmt->execute()) {
            throw new Exception('Failed to delete from members');
        }
        $stmt->close();

        $stmt = $this->conn->prepare("DELETE FROM `log` WHERE member_id = ?");
        $stmt->bind_param("i", $member_id);

        if (!$stmt->execute()) {
            throw new Exception('Failed to delete from members');
        }
        $stmt->close();

        return ['res_code' => '00', 'res_text' => 'ลบข้อมูลสำเร็จ'];

    } catch (Exception $e) {
        return ['res_code' => '01', 'res_text' => 'ลบข้อมูลไม่สำเร็จ: ' . $e->getMessage()];
    }
}


public function images($member_id, $image_file) {
    try {
        if (is_null($image_file)) {
            $stmt = $this->conn->prepare("INSERT INTO images (member_id, image_file) VALUES (?, NULL)");

            $stmt->bind_param("i", $member_id);

            if ($stmt->execute()) {
                $response = array("member_id" => $member_id);
                $stmt->close();
                return $response;
            } else {
                $stmt->close();
                return NULL;
            }
        } else {
            $stmt = $this->conn->prepare("
                UPDATE images 
                SET image_file = ?
                WHERE member_id = ?
            ");

            $stmt->bind_param("si", $image_file, $member_id);

            $stmt->send_long_data(0, $image_file);

            if ($stmt->execute()) {
                $response = [
                    "member_id" => $member_id,
                    "member_path" => $image_file,
                ];
                $stmt->close();
                return $response;
            } else {
                $stmt->close();
                return NULL;
            }
        }
    } catch (Exception $e) {
        return NULL;
    }
}

public function getMemberDetail($member_id) {
    try {
        $stmt = $this->conn->prepare("SELECT 
            m.member_id, 
            m.member_fname, 
            m.member_lname, 
            m.member_email, 
            m.create_date, 
            img.image_file
        FROM 
            members m
            images img  
            ON m.member_id = img.member_id
        WHERE 
            m.member_id = ?");

        $stmt->bind_param("i", $member_id);
        $stmt->execute();
        
        $result = $stmt->get_result();
        if ($result->num_rows > 0) {
            $response = $result->fetch_assoc();

            // echo $response['image_file']; 
            // if (!empty($response['image_file'])) {
            //     $response['image_file'] = base64_encode($response['image_file']);
            //     header('Content-Type: image/jpeg'); 
            //     echo $response['image_file'];

            // } else {
            //     $response['image_file'] = null; 
            // }
  
            $stmt->close();
            return $response; 
        } else {
            $stmt->close();
            return []; 
        }

    } catch (Exception $e) {
        error_log($e->getMessage()); 
        return []; 
    }
}

    //   public function log($member_id,$log_token) {
    //       $stmt = $this->conn->prepare("INSERT INTO `log`(`member_id`, `log_token`, `create_date`) VALUES ('$member_id','$log_token',NOW())");

    //       if($member_id != null){
    //            $stmt = $this->conn->prepare("UPDATE `log` SET log_token = ? WHERE member_id = ?");
    //       }
    //       if($stmt->execute()){
    //         return true;
    //       }else{
    //         return false;
    //       }
    //   }

    public function log($member_id, $log_token) {
        $checkStmt = $this->conn->prepare("SELECT member_id FROM `log` WHERE member_id = ?");
        $checkStmt->bind_param("i", $member_id);
        $checkStmt->execute();
        $checkStmt->store_result(); 
    
        if ($checkStmt->num_rows > 0) {
            $stmt = $this->conn->prepare("UPDATE `log` SET log_token = ?, create_date = NOW() WHERE member_id = ?");
            $stmt->bind_param("si", $log_token, $member_id);
        } else {
        
            $stmt = $this->conn->prepare("INSERT INTO `log`(`member_id`, `log_token`, `create_date`) VALUES (?, ?, NOW())");
            $stmt->bind_param("is", $member_id, $log_token);
        }
    
        $checkStmt->close();  
        if ($stmt->execute()) {
            $stmt->close();
            return true;
        } else {
            $stmt->close();
            return false;
        }
    }

      public function banner() {
          $stmt = $this->conn->prepare("SELECT * FROM `banner`");
          $stmt->execute();
          $result = $stmt->get_result();
          $output = array();
          if($result->num_rows > 0){
            while($res = $result->fetch_assoc())
            {
              $response = array(
                "banner_title" => $res['banner_title']
              );
              $output[]=$response;
            }
            $stmt->close();
            return $output;
          }else{
            $stmt->close();
            return NULL;
          }
      }

      public function isValidApiKey($api_key) {
        $stmt = $this->conn->prepare("SELECT member_id from `log` WHERE log_token = '$api_key' ");
        $stmt->execute();
        $result = $stmt->get_result();
        $num_rows = $result->num_rows;
        $stmt->close();
        return $num_rows > 0;

    }

    public function getUserId($api_key) {
        $stmt = $this->conn->prepare("SELECT member_id from `log` WHERE log_token = '$api_key' ");
        if ($stmt->execute()) {
            $stmt->bind_result($user_id);
            $stmt->fetch();
            $stmt->close();
            return $user_id;
        } else {
            return NULL;
        }
    }

    }

?>
