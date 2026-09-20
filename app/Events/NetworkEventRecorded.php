<?php

namespace App\Events;

use App\Models\NetworkEvent;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class NetworkEventRecorded
{
    use Dispatchable, SerializesModels;

    public function __construct(
        public NetworkEvent $networkEvent
    ) {}
}
