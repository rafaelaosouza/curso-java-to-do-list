package br.com.cursojava.todolist.user;

import at.favre.lib.crypto.bcrypt.BCrypt;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/users")
public class UserController {

	@Autowired
	private IUserRepository userRepository;

	@PostMapping("/create")
	public ResponseEntity create(@RequestBody  UserModel userModel) {
		var userExists = this.userRepository.findByUsername(userModel.getUsername());

		if(userExists != null){
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("User already exists");
		}

		var passwordHarshred = BCrypt.withDefaults()
				.hashToString(12, userModel.getPassword().toCharArray());

		userModel.setPassword(passwordHarshred);

		var userCreated = this.userRepository.save(userModel);
		return ResponseEntity.status(HttpStatus.CREATED).body(userCreated);

	}
}
