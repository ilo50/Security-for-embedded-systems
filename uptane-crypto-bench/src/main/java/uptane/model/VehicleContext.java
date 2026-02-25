package uptane.model;

/**
 * Identity and state of a vehicle's Primary ECU.
 * Used to select the correct target and enforce anti-rollback.
 */
public record VehicleContext(
        String recipientId,
        String hardwareId,
        int currentVersion
) {}
