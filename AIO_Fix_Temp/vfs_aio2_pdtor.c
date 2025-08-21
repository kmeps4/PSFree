int sys_aio_init(struct thread *td, aio_init_args *uap)
{
    return __aio_init(td, uap->param, uap->size, uap->reserved4, uap->reserved5);
}

int __aio_init(
    struct thread *td,
    SceKernelAioParam* param,
    u_int size,
    u_long reserved4,
    u_int reserved5)
{
    // ...

    if (param == NULL
        || ctx != &aio_ctxs[0]
        || aio_ctxs[0].state != 0
    ) {
init:
        sx_xunlock(&aio_sx);
        error = aio_init_params(init_sched_params, ctx);
        if (error != 0) {
            print_err(error);
        }
        goto done;
    }

    // ...

done:
    return error;
unlock:
    sx_xunlock(&aio_sx);
    goto done;
}

int aio_init_ctx(int init_sched_params, struct aio_context *ctx)
{
    // ...
    if (aio_ehs[0] == 0) {
        aio_ehs[0] = EVENTHANDLER_REGISTER(
            "process_suspend_phase4",
            process_suspend4_handler,
            NULL,
            EVENTHANDLER_PRI_LAST
        );
        aio_ehs[1] = EVENTHANDLER_REGISTER(
            "process_suspend_phase1_end",
            process_suspend1_handler,
            NULL,
            EVENTHANDLER_PRI_LAST
        );
        aio_ehs[2] = EVENTHANDLER_REGISTER(
            "process_resume_phase2",
            process_resume_handler,
            NULL,
            EVENTHANDLER_PRI_LAST
        );
        aio_ehs[3] = EVENTHANDLER_REGISTER(
            "process_dtor",
            process_dtor_handler, // !!!
            NULL,
            EVENTHANDLER_PRI_LAST
        );
        aio_ehs[4] = EVENTHANDLER_REGISTER(
            "process_exit",
            process_exit_handler,
            NULL,
            EVENTHANDLER_PRI_LAST
        );
        aio_ehs[5] = EVENTHANDLER_REGISTER(
            "process_exit_fd_closed",
            process_exit_fd_closed_handler,
            NULL,
            EVENTHANDLER_PRI_LAST
        );

        // ...
    }
    // ...
}
