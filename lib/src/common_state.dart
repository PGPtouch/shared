import 'dart:async';

import 'package:meta/meta.dart';

abstract base class CommonState<
  S extends CommonState<S, E>,
  E extends Event<S>
> {
  final StreamController<E> _eventController = StreamController<E>.broadcast();
  E? _lastEvent;

  @nonVirtual
  Stream<E> get events => _eventController.stream;
  E? get lastEvent => _lastEvent;

  @mustCallSuper
  Future<void> dispose() async => await _eventController.close();
  @protected
  @mustCallSuper
  void emit(E event) {
    _eventController.add(event);
    _lastEvent = event;
  }

  CommonState();
}

base mixin StartableCommonState<S extends CommonState<S, E>, E extends Event<S>>
    implements CommonState<S, E> {
  Future<void> start();
}

base mixin CommonStateWithData<
  S extends CommonState<S, E>,
  E extends Event<S>,
  D extends Object?
>
    implements CommonState<S, E> {
  D? _data;
  D? get data => _data;
  set data(D? d) {
    _data = d;
  }
}

abstract class Event<S extends CommonState<S, Event<S>>> {}
