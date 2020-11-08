package com.mhp.coding.challenges.auth.inbound;

import com.mhp.coding.challenges.auth.core.entities.Door;
import com.mhp.coding.challenges.auth.core.inbound.DoorProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/v1/door")
public class DoorController {

    private final DoorProvider doorProvider;

    public DoorController(DoorProvider doorProvider) {
        this.doorProvider = doorProvider;
    }

    @Secured({"ROLE_ADMIN", "ROLE_USER"})
    @GetMapping
    @ResponseBody
    public ResponseEntity<List<Door>> listDoors() {
        return ResponseEntity.ok(this.doorProvider.triggerDoorListing());
    }

    @Secured("ROLE_ADMIN")
    @PostMapping
    public ResponseEntity changeDoorState(@RequestBody Door door) {
        Door newDoor = this.doorProvider.triggerDoorStateChange(door);
        return newDoor == null ? ResponseEntity.badRequest().build() : ResponseEntity.ok(newDoor);
    }

}
